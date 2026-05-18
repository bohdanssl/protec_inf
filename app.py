import os
from flask import Flask, render_template, request, send_file, Response, send_from_directory, abort
from lab1_logic.logic import LCG, SystemGenerator, PiEstimator, FileManager
from werkzeug.utils import secure_filename

from lab2_logic.md5 import MD5Hasher

from lab3_logic.rc5 import FileManagerRC5

from lab4_logic.rsa_cipher import RSAFileManager

from lab5_logic.dss_logic import DSSManager


app = Flask(__name__)
FILENAME = 'example.txt'

app.config['UPLOAD_FOLDER'] = 'uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

@app.route('/')
def index():
    return render_template('main.html')

@app.route('/lab1', methods=['GET', 'POST'])
def lab1():
    if request.method == 'POST':
        k = int(request.form.get('k_val', 100000))
        lcg = LCG()
        sys_gen = SystemGenerator()
        c = lcg.generate(k)
        system_random = sys_gen.generate(k)
        pi_lcg = PiEstimator.estimate_cesaro(c)
        pi_sys = PiEstimator.estimate_cesaro(system_random)
        period_result = lcg.get_period()
        FileManager.save_sequence(FILENAME, c)
        return render_template('lab1/lab1.html', k=k, pi_lcg=pi_lcg, pi_sys=pi_sys, period_result=period_result, posl=c[:10], generated=True)
    return render_template('lab1/lab1.html', generated=False)

def _process_lab2_text(text):
    hasher = MD5Hasher()
    return hasher.compute_hash(text), f"Текст: '{text}'", None

def _process_lab2_file(uploaded_file, action, expected_hash, upload_folder):
    hasher = MD5Hasher()
    filename = secure_filename(uploaded_file.filename)
    filepath = os.path.join(upload_folder, filename)
    uploaded_file.save(filepath)

    result_hash = hasher.compute_file_hash(filepath)
    original_input = f"Файл: {filename}"
    is_valid = None

    if action == 'verify':
        expected_hash = expected_hash.strip().upper()
        is_valid = (result_hash == expected_hash)
        original_input += f" | Очікуваний: {expected_hash}"

    os.remove(filepath)
    return result_hash, original_input, is_valid

@app.route('/lab2', methods=['GET', 'POST'])
def lab2():
    if request.method == 'POST':
        action = request.form.get('action')
        result_hash, original_input, is_valid = None, "", None

        if action == 'text' and request.form.get('text_input'):
            result_hash, original_input, is_valid = _process_lab2_text(request.form.get('text_input'))
        elif action in ['file', 'verify']:
            uploaded_file = request.files.get('file_input')
            if uploaded_file and uploaded_file.filename != '':
                expected = request.form.get('expected_hash', '')
                result_hash, original_input, is_valid = _process_lab2_file(
                    uploaded_file, action, expected, app.config['UPLOAD_FOLDER']
                )

        return render_template('lab2/lab2.html', 
                               result_hash=result_hash, 
                               original_input=original_input, 
                               is_valid=is_valid, 
                               action=action, 
                               generated=True)

    return render_template('lab2/lab2.html', generated=False)



def _process_lab3_file(action, passphrase, uploaded_file, upload_folder):
    filename = secure_filename(uploaded_file.filename)
    filepath = os.path.join(upload_folder, filename)
    uploaded_file.save(filepath)

    if action == 'encrypt':
        output_filename = f"encrypted_{filename}"
    else:
        output_filename = filename.replace('encrypted_', 'decrypted_')
        if output_filename == filename: 
            output_filename = f"decrypted_{filename}"
            
    output_filepath = os.path.join(upload_folder, output_filename)

    try:
        if action == 'encrypt':
            FileManagerRC5.encrypt_file(filepath, output_filepath, passphrase)
        else:
            FileManagerRC5.decrypt_file(filepath, output_filepath, passphrase)
        return {'ready_file': output_filename}
    except Exception as e:
        return {'error_msg': str(e)}
    finally:
        if os.path.exists(filepath):
            os.remove(filepath)

@app.route('/lab3', methods=['GET', 'POST'])
def lab3():
    if request.method == 'POST':
        action = request.form.get('action')
        passphrase = request.form.get('passphrase')
        uploaded_file = request.files.get('file_input')

        if uploaded_file and uploaded_file.filename != '' and passphrase:
            context = _process_lab3_file(action, passphrase, uploaded_file, app.config['UPLOAD_FOLDER'])
            return render_template('lab3/lab3.html', **context)

    return render_template('lab3/lab3.html')



def _process_lab4_crypto(action, uploaded_file, key_file, upload_folder):
    input_filename = secure_filename(uploaded_file.filename)
    key_filename = secure_filename(key_file.filename)
    
    input_path = os.path.join(upload_folder, input_filename)
    key_path = os.path.join(upload_folder, key_filename)

    uploaded_file.save(input_path)
    key_file.save(key_path)

    rsa_manager = RSAFileManager()

    if action == 'encrypt':
        output_filename = f"rsa_enc_{input_filename}"
        output_path = os.path.join(upload_folder, output_filename)
        rsa_manager.encrypt_file(input_path, output_path, key_path)
    else:
        output_filename = input_filename.replace("rsa_enc_", "dec_", 1) if input_filename.startswith("rsa_enc_") else f"dec_{input_filename}"
        output_path = os.path.join(upload_folder, output_filename)
        rsa_manager.decrypt_file(input_path, output_path, key_path)

    return {'ready_file': output_filename}

@app.route('/lab4', methods=['GET', 'POST'])
def lab4():
    if request.method == 'POST':
        action = request.form.get('action')
        uploaded_file = request.files.get('file_input')
        key_file = request.files.get('key_file')

        if uploaded_file and key_file:
            try:
                context = _process_lab4_crypto(action, uploaded_file, key_file, app.config['UPLOAD_FOLDER'])
                return render_template('lab4/lab4.html', **context)
            except Exception as e:
                return render_template('lab4/lab4.html', error_msg=f"Помилка обробки: {str(e)}")
            
    return render_template('lab4/lab4.html')



def _save_uploaded_file(file_obj, upload_folder):
    """Saves a file and returns its path, or None if invalid."""
    if not file_obj or file_obj.filename == '':
        return None
    filename = secure_filename(file_obj.filename)
    path = os.path.join(upload_folder, filename)
    file_obj.save(path)
    return path

def _lab5_sign_text(dss, req, upload_folder):
    text = req.form.get('text_input', '')
    priv_path = _save_uploaded_file(req.files.get('private_key_file'), upload_folder)
    
    if not priv_path:
        return {'text_input': text, 'error_msg': "Оберіть файл закритого ключа (Private Key)!"}
    
    sig = dss.sign_data(text.encode('utf-8'), priv_path)
    return {'text_input': text, 'signature_output': sig, 'success_msg': "Текст підписано!"}

def _lab5_verify_text(dss, req, upload_folder):
    text = req.form.get('text_input', '')
    sig_input = req.form.get('signature_input', '')
    pub_path = _save_uploaded_file(req.files.get('public_key_file'), upload_folder)
    
    if not pub_path:
        return {'text_input': text, 'signature_input': sig_input, 'error_msg': "Оберіть файл відкритого ключа (Public Key)!"}
    
    is_valid = dss.verify_data(text.encode('utf-8'), sig_input, pub_path)
    return {'text_input': text, 'signature_input': sig_input, 'valid_text': is_valid}

def _lab5_sign_file(dss, req, upload_folder):
    filepath = _save_uploaded_file(req.files.get('file_input'), upload_folder)
    priv_path = _save_uploaded_file(req.files.get('private_key_file'), upload_folder)
    
    if not filepath or not priv_path:
        return {'error_msg': "Оберіть документ та файл закритого ключа!"}
    
    sig_hex = dss.sign_file(filepath, priv_path)
    filename = os.path.basename(filepath)
    sig_filename = f"{filename}.sig"
    sig_filepath = os.path.join(upload_folder, sig_filename)
    
    with open(sig_filepath, "w") as sf:
        sf.write(sig_hex)
        
    return {'ready_file': sig_filename, 'success_msg': "Файл підписано!"}

def _lab5_verify_file(dss, req, upload_folder):
    filepath = _save_uploaded_file(req.files.get('file_input'), upload_folder)
    pub_path = _save_uploaded_file(req.files.get('public_key_file'), upload_folder)
    sig_file = req.files.get('sig_file_input')
    
    if not filepath or not pub_path or not sig_file:
        return {'error_msg': "Оберіть усі 3 файли (документ, підпис та відкритий ключ)!"}
        
    sig_hex = sig_file.read().decode('utf-8').strip()
    is_valid = dss.verify_file(filepath, sig_hex, pub_path)
    return {'valid_file': is_valid}

@app.route('/lab5', methods=['GET', 'POST'])
def lab5():
    if request.method == 'POST':
        action = request.form.get('action')
        dss = DSSManager()
        upload_dir = app.config['UPLOAD_FOLDER']
        context = {}

        try:
            if action == 'generate_keys':
                priv_path = os.path.join(upload_dir, 'dsa_private.pem')
                pub_path = os.path.join(upload_dir, 'dsa_public.pem')
                dss.generate_and_save_keys(priv_path, pub_path)
                context = {'success_msg': "Ключі успішно згенеровано! Скачайте їх собі на комп'ютер."}
            elif action == 'sign_text':
                context = _lab5_sign_text(dss, request, upload_dir)
            elif action == 'verify_text':
                context = _lab5_verify_text(dss, request, upload_dir)
            elif action == 'sign_file':
                context = _lab5_sign_file(dss, request, upload_dir)
            elif action == 'verify_file':
                context = _lab5_verify_file(dss, request, upload_dir)

            return render_template('lab5/lab5.html', **context)

        except Exception as e:
            return render_template('lab5/lab5.html', error_msg=f"Помилка обробки: {str(e)}")

    return render_template('lab5/lab5.html')