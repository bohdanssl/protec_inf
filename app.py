import os
from flask import Flask, render_template, request, send_file, Response, send_from_directory, abort
from lab1_logic.logic import LCG, SystemGenerator, PiEstimator, FileManager

from lab2_logic.md5 import MD5Hasher

from lab3_logic.rc5 import FileManagerRC5

from lab4_logic.rsa_cipher import RSAFileManager

from lab5_logic.dss_logic import DSSManager


#app

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

@app.route('/lab2', methods=['GET', 'POST'])
def lab2():
    if request.method == 'POST':
        action = request.form.get('action')
        hasher = MD5Hasher()
        result_hash = None
        original_input = ""
        is_valid = None

        if action == 'text':
            text = request.form.get('text_input', '')
            if text:
                result_hash = hasher.compute_hash(text)
                original_input = f"Текст: '{text}'"

        elif action == 'file' or action == 'verify':
            uploaded_file = request.files.get('file_input')
            if uploaded_file and uploaded_file.filename != '':
                filename = uploaded_file.filename
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                uploaded_file.save(filepath)

                result_hash = hasher.compute_file_hash(filepath)
                original_input = f"Файл: {filename}"

                if action == 'verify':
                    expected_hash = request.form.get('expected_hash', '').strip().upper()
                    is_valid = (result_hash == expected_hash)
                    original_input += f" | Очікуваний: {expected_hash}"

                os.remove(filepath)

        return render_template('lab2/lab2.html', 
                               result_hash=result_hash, 
                               original_input=original_input, 
                               is_valid=is_valid, 
                               action=action, 
                               generated=True)

    return render_template('lab2/lab2.html', generated=False)

@app.route('/lab3', methods=['GET', 'POST'])
def lab3():
    if request.method == 'POST':
        action = request.form.get('action')
        passphrase = request.form.get('passphrase')
        uploaded_file = request.files.get('file_input')

        if uploaded_file and uploaded_file.filename != '' and passphrase:
            filename = uploaded_file.filename
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            uploaded_file.save(filepath)

            if action == 'encrypt':
                output_filename = f"encrypted_{filename}"
            else:
                output_filename = filename.replace('encrypted_', 'decrypted_')
                if output_filename == filename: 
                    output_filename = f"decrypted_{filename}"
                    
            output_filepath = os.path.join(app.config['UPLOAD_FOLDER'], output_filename)

            try:
                if action == 'encrypt':
                    FileManagerRC5.encrypt_file(filepath, output_filepath, passphrase)
                else:
                    FileManagerRC5.decrypt_file(filepath, output_filepath, passphrase)
                
                return render_template('lab3/lab3.html', ready_file=output_filename)
            except Exception as e:
                return render_template('lab3/lab3.html', error_msg=str(e))
            finally:
                if os.path.exists(filepath):
                    os.remove(filepath)

    return render_template('lab3/lab3.html')

@app.route('/download_hash', methods=['POST'])
def download_hash():
    hash_value = request.form.get('hash_value')
    return Response(
        hash_value,
        mimetype="text/plain",
        headers={"Content-disposition": "attachment; filename=md5_result.txt"}
    )

import os
from werkzeug.utils import secure_filename
from lab4_logic.rsa_cipher import RSAFileManager 

@app.route('/lab4', methods=['GET', 'POST'])
def lab4():
    if request.method == 'POST':
        action = request.form.get('action')
        uploaded_file = request.files.get('file_input')
        key_file = request.files.get('key_file')

        if uploaded_file and key_file:
            try:
                input_filename = secure_filename(uploaded_file.filename)
                key_filename = secure_filename(key_file.filename)
                
                input_path = os.path.join(app.config['UPLOAD_FOLDER'], input_filename)
                key_path = os.path.join(app.config['UPLOAD_FOLDER'], key_filename)

                uploaded_file.save(input_path)
                key_file.save(key_path)

                rsa_manager = RSAFileManager()

                if action == 'encrypt':
                    output_filename = "rsa_enc_" + input_filename
                    output_path = os.path.join(app.config['UPLOAD_FOLDER'], output_filename)
                    rsa_manager.encrypt_file(input_path, output_path, key_path)
                    
                elif action == 'decrypt':
                    if input_filename.startswith("rsa_enc_"):
                        output_filename = input_filename.replace("rsa_enc_", "dec_", 1)
                    else:
                        output_filename = "dec_" + input_filename
                        
                    output_path = os.path.join(app.config['UPLOAD_FOLDER'], output_filename)
                    rsa_manager.decrypt_file(input_path, output_path, key_path)

                return render_template('lab4/lab4.html', ready_file=output_filename)

            except Exception as e:
                return render_template('lab4/lab4.html', error_msg=f"Помилка обробки: {str(e)}")
            
    return render_template('lab4/lab4.html')


@app.route('/lab4_generate', methods=['POST'])
def lab4_generate():
    try:
        rsa_manager = RSAFileManager(key_size=2048)
        
        pub_path = os.path.join(app.config['UPLOAD_FOLDER'], 'public.pem')
        priv_path = os.path.join(app.config['UPLOAD_FOLDER'], 'private.pem')
        
        rsa_manager.generate_and_save_keys(private_file=priv_path, public_file=pub_path)
        
        return render_template('lab4/lab4.html', keys_generated=True)
    except Exception as e:
        return render_template('lab4/lab4.html', error_msg=f"Помилка генерації: {str(e)}")

# ======================= ЛАБОРАТОРНА 5 =======================
@app.route('/lab5', methods=['GET', 'POST'])
def lab5():
    if request.method == 'POST':
        action = request.form.get('action')
        dss = DSSManager()

        # Шляхи для збереження згенерованих ключів (Крок 1) залишаються
        default_priv_path = os.path.join(app.config['UPLOAD_FOLDER'], 'dsa_private.pem')
        default_pub_path = os.path.join(app.config['UPLOAD_FOLDER'], 'dsa_public.pem')

        try:
            # --- 1. ГЕНЕРАЦІЯ КЛЮЧІВ ---
            if action == 'generate_keys':
                dss.generate_and_save_keys(default_priv_path, default_pub_path)
                return render_template('lab5/lab5.html', success_msg="Ключі успішно згенеровано! Скачайте їх собі на комп'ютер.")

            elif action == 'sign_text':
                text = request.form.get('text_input', '')
                priv_key_file = request.files.get('private_key_file')
                
                if not priv_key_file or priv_key_file.filename == '':
                    return render_template('lab5/lab5.html', text_input=text, error_msg="Оберіть файл закритого ключа (Private Key)!")
                
                priv_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(priv_key_file.filename))
                priv_key_file.save(priv_path)
                
                sig = dss.sign_data(text.encode('utf-8'), priv_path)
                return render_template('lab5/lab5.html', text_input=text, signature_output=sig, success_msg="Текст підписано!")

            elif action == 'verify_text':
                text = request.form.get('text_input', '')
                sig_input = request.form.get('signature_input', '')
                pub_key_file = request.files.get('public_key_file')
                
                if not pub_key_file or pub_key_file.filename == '':
                    return render_template('lab5/lab5.html', text_input=text, signature_input=sig_input, error_msg="Оберіть файл відкритого ключа (Public Key)!")
                
                pub_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(pub_key_file.filename))
                pub_key_file.save(pub_path)
                
                is_valid = dss.verify_data(text.encode('utf-8'), sig_input, pub_path)
                return render_template('lab5/lab5.html', text_input=text, signature_input=sig_input, valid_text=is_valid)

            elif action == 'sign_file':
                uploaded_file = request.files.get('file_input')
                priv_key_file = request.files.get('private_key_file')
                
                if not uploaded_file or not priv_key_file or priv_key_file.filename == '':
                    return render_template('lab5/lab5.html', error_msg="Оберіть документ та файл закритого ключа!")
                
                filename = secure_filename(uploaded_file.filename)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                uploaded_file.save(filepath)
                
                priv_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(priv_key_file.filename))
                priv_key_file.save(priv_path)
                
                sig_hex = dss.sign_file(filepath, priv_path)
                
                sig_filename = f"{filename}.sig"
                sig_filepath = os.path.join(app.config['UPLOAD_FOLDER'], sig_filename)
                with open(sig_filepath, "w") as sf:
                    sf.write(sig_hex)
                    
                return render_template('lab5/lab5.html', ready_file=sig_filename, success_msg="Файл підписано!")

            elif action == 'verify_file':
                uploaded_file = request.files.get('file_input')
                sig_file = request.files.get('sig_file_input')
                pub_key_file = request.files.get('public_key_file')
                
                if not uploaded_file or not sig_file or not pub_key_file or pub_key_file.filename == '':
                    return render_template('lab5/lab5.html', error_msg="Оберіть усі 3 файли (документ, підпис та відкритий ключ)!")
                    
                filename = secure_filename(uploaded_file.filename)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                uploaded_file.save(filepath)
                
                pub_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(pub_key_file.filename))
                pub_key_file.save(pub_path)
                
                sig_hex = sig_file.read().decode('utf-8').strip()
                is_valid = dss.verify_file(filepath, sig_hex, pub_path)
                
                return render_template('lab5/lab5.html', valid_file=is_valid)

        except Exception as e:
            return render_template('lab5/lab5.html', error_msg=f"Помилка обробки: {str(e)}")

    return render_template('lab5/lab5.html')

@app.route('/download/<filename>')
def download_file(filename):
    try:
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)
    except FileNotFoundError:
        return "Файл не знайдено", 404

@app.route('/download')
def download():
    if FileManager.exists(FILENAME):
        return send_file(FILENAME, as_attachment=True)
    return "Файл не знайдено", 404

if __name__ == '__main__':
    app.run(debug=True)