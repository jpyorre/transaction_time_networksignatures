import zipfile
import os
import re

def unzip_files_with_password():
    files = os.listdir('.')
    pattern = re.compile(r'(\d{4}-\d{2}-\d{2})') # pattern to match the filenames and extract the date
    
    for file in files:
        if file.endswith('.zip'):
            match = pattern.search(file) # Extract the date from the filename
            if match:
                date_str = match.group(1)
                date_str = date_str.replace('-', '')
                password = f'infected_{date_str}' # Construct the password
                
                # Attempt to unzip the file with the password
                try:
                    with zipfile.ZipFile(file, 'r') as zip_ref:
                        zip_ref.extractall(pwd=password.encode())
                    print(f'Successfully unzipped {file} with password: {password}')
                except zipfile.BadZipFile:
                    print(f'Error: {file} is not a valid zip file.')
                except RuntimeError as e:
                    if 'Bad password' in str(e):
                        print(f'Failed to unzip {file}. Incorrect password.')
                    else:
                        print(f'Failed to unzip {file}. Error: {e}')
                except Exception as e:
                    print(f'An unexpected error occurred while unzipping {file}. Error: {e}')

if __name__ == "__main__":
    unzip_files_with_password()