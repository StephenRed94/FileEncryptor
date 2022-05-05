import PySimpleGUI as psg
from File import File
from cryptography.fernet import Fernet
import os
import re


def encrypt_file():
    secure_file = open(file.path, "r")
    data = secure_file.read()
    secure_file.close()
    key = Fernet.generate_key()
    fernet = Fernet(key)
    encoded_message = fernet.encrypt(data.encode())
    window['contents'].update(encoded_message)
    window['status'].update('File Status: Encrypted')
    window['password'].update('')
    window['path'].update('File Path: ' + file.path)
    window['name'].update('File Name: ' + file.name)


def decrypt_file():
    secure_file = open(file.path, "r")
    window['contents'].update(secure_file.read())
    window['status'].update('File Status: Decrypted')
    window['password'].update('')
    secure_file.close()


def save_file():
    secure_file = open(file.path, "w")
    secure_file.write(file.contents)
    window['status'].update('File Status: Changes Saved.')
    secure_file.close()


layout1 = [
    [psg.FileBrowse('Choose File To Encrypt/Decrypt', key='-IN-')],
    [psg.Text('File Path: ', key='path')],
    [psg.Text('File Name: ', key='name')],
    [psg.Button('Encrypt')],
    [psg.Button('Decrypt')],
    [psg.Button('Save Changes')]
]
layout2 = [
    [psg.Text('Enter Password'), psg.Input('', key='password', password_char='*')],
    [psg.Text('Re-enter Password', key='pass2'), psg.Input('', key='password2', password_char='*')],
    [psg.Text('File Status: ', key='status')],
    [psg.Text('File Contents:')],
    [psg.Multiline(key='contents', size=(60, 10))]
]

layout = [
    [psg.Column(layout1), psg.Column(layout2)],
]
window = psg.Window('File Encryptor', layout)
attempts = 0
isDecrypted = False
while True:
    event, values = window.read()
    try:
        file = File((str(os.path.basename(values['-IN-']))), (str(values['password'])), (str(values['-IN-'])),
                    (str(values['contents'])))
    except:
        print("Program Ended.")
    if event in (None, 'Exit'):
        break
    elif event in 'Encrypt':
        password = str(values['password'])
        second_password = str(values['password2'])
        if file.path != '':
            if file.password != '':
                if file.password == 'test':
                    window['password2'].update(visible=False)
                    window['pass2'].update('')
                    encrypt_file()
                    isDecrypted = False
                elif (len(file.password) < 6) or (len(file.password) > 11):
                    window['status'].update('File Status: Failed To Encrypt. Password must be between 6 and 10 \n'
                                            'characters in length and contain at least 1 lower case letter, '
                                            '1 upper \n '
                                            'case letter, 1 number, and 1 special character.')
                elif not re.search("[a-z]", file.password):
                    window['status'].update('File Status: Failed To Encrypt. Password must be between 6 and 10 \n'
                                            'characters in length and contain at least 1 lower case letter, '
                                            '1 upper \n '
                                            'case letter, 1 number, and 1 special character.')
                elif not re.search("[A-Z]", file.password):
                    window['status'].update('File Status: Failed To Encrypt. Password must be between 6 and 10 \n'
                                            'characters in length and contain at least 1 lower case letter, '
                                            '1 upper \n '
                                            'case letter, 1 number, and 1 special character.')
                elif not re.search("[0-9]", file.password):
                    window['status'].update('File Status: Failed To Encrypt. Password must be between 6 and 10 \n'
                                            'characters in length and contain at least 1 lower case letter, '
                                            '1 upper \n '
                                            'case letter, 1 number, and 1 special character.')
                elif not re.search("[!#$%&'()*+,-./:;<=>?@\]^_`{|}~)]", file.password):
                    window['status'].update('File Status: Failed To Encrypt. Password must be between 6 and 10 \n'
                                            'characters in length and contain at least 1 lower case letter, '
                                            '1 upper \n '
                                            'case letter, 1 number, and 1 special character.')
                else:
                    if password == second_password:
                        window['password2'].update(visible=False)
                        window['pass2'].update('')
                        encrypt_file()
                        isDecrypted = False
                    else:
                        window['status'].update("File Status: Failed To Encrypt. Passwords don't match.")
            elif file.password == '':
                window['status'].update('File Status: Failed To Encrypt. Password Required.')
        else:
            window['status'].update('File Status: Failed To Encrypt. No file selected.')
    elif event in 'Decrypt':
        try:
            if password == file.password:
                window['password2'].update('')
                window['password2'].update(visible=True)
                window['pass2'].update('Re-enter Password')
                decrypt_file()
                isDecrypted = True
            else:
                if attempts < 4:
                    attempts += 1
                    window['status'].update(
                        'File Status: Failed To Decrypt. Password Incorrect. ' + str(5 - attempts)
                        + ' attempts remaining')
                else:
                    window.close()
        except:
            window['status'].update('File Status: Failed To Decrypt. No File Selected.')
    elif event in 'Save Changes':
        try:
            if isDecrypted:
                save_file()
            else:
                window['status'].update('File Status: Changes Not Saved. File Encrypted.')
        except:
            window['status'].update('File Status: Changes Not Saved. No File Selected.')

window.close()
