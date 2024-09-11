# GMOrthentication

Bare bones encrypted desktop application for managing authentication requests. 

# Set up

1. Install python python 3.11
2. Install required dependencies in requirements.txt

## Usage

1. Start by entering a password **under 16 characters long**. This will generate nonce.txt which will be used in AES
   encryption to encrypt your accounts. You'll need to remember the password for future access.
2. Add sites by filling out the form and clicking submit. Make sure to put the OTP secret code on the "Secret" field.
3. When you want to get an up to date OTP code click refresh, or re-loggin. 