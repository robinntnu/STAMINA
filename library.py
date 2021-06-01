'''
  Author: Robin Berg Jønsson
  Created: 23.04.2021
  Last edited:
  Description: This file represents a code library, holding the necessary methods to perform the experiments,
               reducing redundant and complex code structures
  Methods:
    1. calculate_hash(file_path, hash_out)
    2. timestamp()
    3. round_two_decimals(decimal_number)
    4. get_number_of_files(file_path, file_count)
    5. get_all_files(file_path, file_type)
    6. get_sub_directories(file_path)
    7. get_all_exe_files_in_directory(file_path)
      7.1 is_exe_file(file_path)
        7.1.1 read_number_of_bytes_from_file(file_path, byte_length)
        7.1.2 get_e_lfanew(binary_data)
        7.1.3 get_pe_signature_position(e_lfanew)
          7.1.3.1 hex_to_decimal(hex_value)
        7.1.4 executable_is_32_or_64_bit(pe_signature_position, binary_data)
    8. copy_files_to_directory(files_array, destination, hash_out)
    9. calculate_entropy(file_path)
    10. binary_to_grayscale_image(file_path, output_path, hash_out='SHA-256')
    11. resize_image(file_path, output_path, image_scale_width=299, image_scale_height=299, hash_out='SHA-256')
      11.1 get_file_name(file_path)
    12. resize_images(input_paths, output_path, image_scale_width=299, image_scale_height=299)
      12.1 show_progress_bar(index, length)
    13. read_virus_total_reports_to_detect_packers(path, database_table)
      13.1 extract_file_hash_from_json_file(file_path)
      13.2 extract_packer_identifier_from_json_file(file_path)
      13.3 read_json_file(file_path)
    14. create_data_batch(image_file_paths, labels=None, batch_size=32, data_type=1)
      14.1 preprocess_image(image_file_path, img_width=299, img_height=299)
      14.2 image_and_label(image_file_path, label)
      14.3 create_boolean_labels(label_array)
    15. k_fold(image_paths, boolean_labels, n_split=10)
    16. stratified_k_fold(image_paths, labels, boolean_labels, n_split=10, shuffle=True)
    17. preprocess_dataset(benign_files_path, malicious_files_path, benign_images_path, malicious_images_path,
                       benign_images_resized_path, malicious_images_resized_path, virus_total_reports_file_path,
                       hash_out, image_scale_width, image_scale_height, database)
    18. preprocess_exe_files(exe_file_path, output_image_path, output_resized_image_path, hash_out,
                         image_scale_width, image_scale_height, database)
    19.
    20.

'''
# Setup
import hashlib
import datetime
import os
import json
import numpy as np
import cv2
from math import sqrt, ceil, log2
from itertools import islice
from pathlib import Path
from sql import Database
import tensorflow as tf
import sys
from shutil import copyfile
from sklearn.preprocessing import LabelEncoder
from sklearn.preprocessing import OneHotEncoder
from sklearn.model_selection import KFold
from sklearn.model_selection import StratifiedKFold
from sklearn.model_selection import train_test_split
from ml_model import Transfer_Learning_Model
from decimal import Decimal
import subprocess

'''
  Nr 1. 
  Method: calculate_hash()
  Args: file_path, hash_out
  Description: Calculates an MD5 or SHA-256 hash of the given file, located at the given file_path, 
               based on the hash_out value being either 'MD5' or 'SHA-256'
'''


def calculate_hash(file_path, hash_out):
    # Creates a variable to build / hold the MD5 / SHA-256 hash
    if hash_out == 'MD5':
        hash_builder = hashlib.md5()
    elif hash_out == 'SHA-256':
        hash_builder = hashlib.sha256()

    # Open the file and reads it as binary
    with open(file_path, "rb") as binary_file:
        # Read 512 bytes at a time
        for read_bytes in iter(lambda: binary_file.read(512), b""):
            hash_builder.update(read_bytes)
    # Returns the hash
    return hash_builder.hexdigest()


'''
    // End of method calculate_hash
'''
'''
  Nr 2. 
  Method: timestamp()
  Args: None
  Description: Returns the current date and time
'''


def timestamp():
    return datetime.datetime.now()


'''
  // End of method timestamp
'''
'''
  Nr 3. 
  Method: round_two_decimals(decimal_number)
  Args: decimal_number
  Description: Returns the given decimal number with two decimal places
'''


def round_two_decimals(decimal_number):
    return round(float(decimal_number), 2)


'''
  // End of method round_two_decimals
'''
'''
  Nr 4. 
  Method: get_number_of_files(file_path, file_count)
  Args: file_path, file_count
  Description: Returns the amount of files specified in file_count from the specified file_path
'''


def get_number_of_files(file_path, file_count):
    # Creates a path
    path = Path(file_path)
    # Return an array with the found paths
    return [file.path for file in islice(os.scandir(path), file_count)]


'''
  // END of method get_number_of_files
'''
'''
  Nr 5. 
  Method: get_all_files(file_path, file_type)
  Args: file_path, file_type
  Description: Returns all files of the specified file_type e.g. .png, etc. from the specified file_path
'''


def get_all_files(file_path, file_type):
    # Creates a path
    path = Path(file_path)
    # Return an array of the found files
    return [file.path for file in os.scandir(path) if file.name.endswith(file_type)]


'''
  // End of method get_all_files
'''
'''
  Nr 6. 
  Method: get_sub_directories(file_path)
  Args: file_path
  Description: Returns all the subdirectories in the specified file_path
'''


def get_sub_directories(file_path):
    # Creates a path
    path = Path(file_path)
    # Return an array of the found subdirectories, if any
    return [file.path.replace(f'{file_path}/', '') for file in os.scandir(path) if file.is_dir()]


'''
  // End of method get_sub_directories
'''
'''
  Nr 7. 
  Method: get_all_exe_files_in_directory(file_path)
  Args: file_path
  Description: Returns all the .exe files in the specified file_path
'''


def get_all_exe_files_in_directory(file_path):
    # 1. Get all files and their absolut path
    all_files = get_all_files(file_path, '')

    # 2. Array holding every file that is a .exe file
    exe_files = []
    # 3. Verify that the file actually is a .exe file
    #    is_exe_file(f)[0] = True / False
    #    is_exe_file(f)[1] = x86 or x64
    for f in all_files:
        if is_exe_file(f)[0]:
            exe_files.append(f)
    # Returns the found files
    return exe_files


'''
  // End of method get_all_exe_files_in_directory
'''
'''
  Nr 7.1
  Method: is_exe_file(file_path)
  Args: file_path
  Description: Verifies that the two first bytes are 4D 5A, then looks for the PE signature 50450000, 
               and then looks for an Intel or AMD x86 or x64 cpu architecture signature.
               Returns a boolean value and the x86, x64 or None the .exe files in the specified file_path
              
'''


def is_exe_file(file_path):
    # Read the first 64 bytes
    binary_data = read_number_of_bytes_from_file(file_path, 64)

    # If the first bytes are 0x4d and 0x5a or 4D 5A in HEX and MZ in ASCII code, the file is EXE
    if binary_data[0:1].hex().upper() == '4D' and binary_data[1:2].hex().upper() == '5A':
        # Getting the pointer to the PE signature
        e_lfanew = get_e_lfanew(binary_data)
        # Gets the PE signature position in the binary_data
        pe_signature_position = get_pe_signature_position(e_lfanew)
        # Reads the last position of the PE signature + 2 to get the executable type
        binary_data = read_number_of_bytes_from_file(file_path, pe_signature_position[1] + 2)
        # Gets the executable type 32 or 64 bit
        executable_type = executable_is_32_or_64_bit(pe_signature_position, binary_data)
        # The PE signature 50450000 is found
        if binary_data[pe_signature_position[0]:pe_signature_position[1]].hex().upper() == '50450000':
            # We are only interested in intel x86 and x64. e.g. 64 AA = Arm, hence executable_type can be None
            if executable_type:
                return [True, executable_type]

    return [False, None]


'''
  // End of method 
'''
'''
  Nr 7.1.1
  Method: read_number_of_bytes_from_file(file_path, byte_length)
  Args: file_path, byte_length
  Description: Reads the given byte_length from the given file_path
'''


def read_number_of_bytes_from_file(file_path, byte_length):
    # Read the first 64 bytes
    with open(file_path, 'rb') as binary_file:
        binary_data = binary_file.read(byte_length)
    # Returns the read data
    return binary_data


'''
  // END of method read_number_of_bytes_from_file
'''
'''
  Nr 7.1.2
  Method: get_e_lfanew(binary_data)
  Args: binary_data
  Description: Reads the given binary_data and extract the e_lfanew pointer to the PE Signature, 
               found at the HEX offset location 3C in a HEX editor, with the length of 4 bytes, 
               hence position [60:64] in decimal. The 4 bytes here are  written in little endian, 
               but the offset value should be in big endian, hence we start reading backwards  
'''


def get_e_lfanew(binary_data):
    return f'{binary_data[63:64].hex().upper()} {binary_data[62:63].hex().upper()} ' \
           f'{binary_data[61:62].hex().upper()} {binary_data[60:61].hex().upper()}'


'''
  // End of method get_e_lfanew(binary_data)
'''
'''
  Nr 7.1.3
  Method: get_pe_signature_position(e_lfanew)
  Args: e_lfanew
  Description: Reads the e_lfanew pointer in HEX, converting it to decimals
'''


def get_pe_signature_position(e_lfanew):
    # Removes whitespace and converts the hex value to decimal
    start_position = int(hex_to_decimal(e_lfanew.replace(' ', '')))
    end_position = start_position + 4
    return [start_position, end_position]


'''
  // END of method get_pe_signature_position
'''
'''
  Nr 7.1.3.1
  Method: hex_to_decimal(hex_value)
  Args: hex_value
  Description: Converts the given hex_value to a decimal value
'''


def hex_to_decimal(hex_value):
    return int(hex_value, 16)


'''
  // END of method hex_to_decimal
'''
'''
  Nr 7.1.4
  Method: executable_is_32_or_64_bit(pe_signature_position, binary_data)
  Args: pe_signature_position, binary_data
  Description: Looks for the Intel and AMD x86 and x64 signature by given the pe_signature_position, 
               and the binary_data where the signature is in
'''


def executable_is_32_or_64_bit(pe_signature_position, binary_data):
    # Gets the executable signature
    executable_type_signature = binary_data[pe_signature_position[1]:pe_signature_position[1] + 2].hex().upper()
    # x86 or x64
    if executable_type_signature == '4C01':  # x86 signature
        return 'x86'
    elif executable_type_signature == '6486':  # x64 signature
        return 'x64'


'''
  // End of method executable_is_32_or_64_bit
'''
'''
  Nr 8
  Method: copy_files_to_directory(files_array, destination, hash_out)
  Args: files_array, destination, hash_out='SHA-256' 
  Description: Copy files from an array with file paths files_array,
               to the destination folder, with the filename as the hash specified in th hash_out.
               Default SHA-256, but could also be MD5
'''


def copy_files_to_directory(files_array, destination, hash_out='SHA-256'):
    counter = 0
    duplicated_files = 0
    for src in files_array:
        # Create a hash as a unique file_name SHA-256 as default or MD5
        file_name = calculate_hash(src, hash_out)
        # If the file exists e.g. there are duplicates in the set, skip that file
        if os.path.exists(f'{destination}/{file_name}'):
            duplicated_files += 1
        else:
            copyfile(src, f'{destination}/{file_name}')
            counter += 1
    print(f'Information: Found {len(files_array)} files, {duplicated_files} where duplicated and '
          f'{counter} where unique and therefore copied to path: {destination}')


'''
  // End of method copy_files_to_directory
'''
'''
  Nr 9
  Method: calculate_entropy(file_path)
  Args: file_path 
  Description: Calculates Shannon's entropy of the file in the given file_path
               in range [0-8]
'''


def calculate_entropy(file_path):
    entropy = 0

    # 1 Opens the file in the file_path as read binary and reads it to the variable binary_data
    with open(file_path, 'rb') as binary_file:
        binary_data = binary_file.read()

    # Calculates the file size
    file_size_in_bytes = len(binary_data)

    # 2 Creats a one dimensional array from the buffer,
    #     where the return type is unsign 8 bit integers,
    #     meaning that it is in the range of 0-255.
    one_dimensional_pixel_stream = np.frombuffer(binary_data, dtype=np.uint8)

    # Creating an array with the length 256
    array = [0] * 256

    for i in one_dimensional_pixel_stream:
        array[i] += 1

    for i in array:
        p = i / file_size_in_bytes
        if p > 0:
            entropy += p * log2(p)

    return -entropy


'''
  // End of method calculate_entropy(file_path)
'''
'''
  Nr 10
  Method: binary_to_grayscale_image(file_path, output_path, hash_out='SHA-256')
  Args: file_path, output_path, hash_out='SHA-256' 
  Description: Converts an .exe file in the file_path into an image saving the result 
               in the output_path, with the image file name as a hash of the .exe file,
               with the hash algorithm given in hash_out. 
               Default SHA-256, but could also be MD5
'''


def binary_to_grayscale_image(file_path, output_path, hash_out='SHA-256'):
    # 1. Opens the file_name as read binary and reads it to the variable binary_data
    with open(file_path, 'rb') as binary_file:
        binary_data = binary_file.read()

    # 1.2 Creats a one dimensional array from the buffer,
    #     where the return type is unsign 8 bit integers,
    #     meaning that it is in the range of 0-255.
    one_dimensional_pixel_stream = np.frombuffer(binary_data, dtype=np.uint8)

    """ 
      Step 2: Reshaping
      The one-dimensional pixel stream is converted into a two-dimensional pixel stream.
      The width is determined by this table:
      +-----------------------+-------------+
      | Pixel File Size       | Image Width |
      +-----------------------+-------------+
      | Between 0 to 10       | 32          |
      +-----------------------+-------------+
      | Between 10 and 30     | 64          |
      +-----------------------+-------------+
      | Between 30 and 60     | 128         |
      +-----------------------+-------------+
      | Between 60 and 100    | 256         |
      +-----------------------+-------------+
      | Between 100 and 200   | 384         |
      +-----------------------+-------------+
      | Between 200 and 1000  | 512         |
      +-----------------------+-------------+
      | Between 1000 and 1500 | 1024        |
      +-----------------------+-------------+
      | Greater than 1500     | 2048        |
      +-----------------------+-------------+
      Then the height is determined by dividing one_dimensional_pixel_stream_size with the image width.
      If the result is a decimal, we round up.  
  """
    # 2.1 The size of the one-dimensional pixel stream
    one_dimensional_pixel_stream_size = len(one_dimensional_pixel_stream)

    # 2.2 Calculate the image width according to the table above
    if 0 >= one_dimensional_pixel_stream_size and one_dimensional_pixel_stream_size <= 10:
        image_width = 32
    elif 10 >= one_dimensional_pixel_stream_size and one_dimensional_pixel_stream_size <= 30:
        image_width = 64
    elif 30 >= one_dimensional_pixel_stream_size and one_dimensional_pixel_stream_size <= 60:
        image_width = 128
    elif 60 >= one_dimensional_pixel_stream_size and one_dimensional_pixel_stream_size <= 100:
        image_width = 256
    elif 100 >= one_dimensional_pixel_stream_size and one_dimensional_pixel_stream_size <= 200:
        image_width = 384
    elif 200 >= one_dimensional_pixel_stream_size and one_dimensional_pixel_stream_size <= 1000:
        image_width = 512
    elif 1000 >= one_dimensional_pixel_stream_size and one_dimensional_pixel_stream_size <= 1500:
        image_width = 1024
    elif one_dimensional_pixel_stream_size > 1500:
        image_width = 2048

    # 2.3 Calculating the image height by dividing one_dimensional_pixel_stream_size with the image width
    #     If the result is a decimal, we round up
    image_height = int(ceil(one_dimensional_pixel_stream_size / image_width))

    # To calculate how many pixels we need as padding, we take the image width times the image height,
    # and then sub tract it from the one dimensional pixel stream size.
    # The padded pixels will all be zeroes.
    lenght_of_extra_pixels_as_zeros = (image_width * image_height) - one_dimensional_pixel_stream_size

    # Concatenate the extra_pixels_as_zeros with the one_dimensional_pixel_stream
    one_dimensional_pixel_stream_with_padding = np.hstack(
        (one_dimensional_pixel_stream, np.zeros(lenght_of_extra_pixels_as_zeros, np.uint8)))

    # Transforming the 1D pixel stream to a 2D pixel stream
    two_dimensional_pixel_stream = np.reshape(one_dimensional_pixel_stream_with_padding, (image_height, image_width))

    # Writing the two_dimensional_pixel_stream to a
    # gray scaled image with the filename as the MD5 hash of the input file
    save_to_path = f'{output_path}/{calculate_hash(file_path, hash_out)}.png'
    cv2.imwrite(save_to_path, two_dimensional_pixel_stream)

    return save_to_path


'''
  // End of method
'''
'''
  Nr 11
  Method: resize_image(file_path, output_path, image_scale_width=299, image_scale_height=299, hash_out='SHA-256')
  Args: file_path, output_path, image_scale_width=299, image_scale_height=299, hash_out='SHA-256'
  Description: Scale the given image in file_path default to 299 x 299, but could be specified in
               image_scale_width and image_scale_height. The image name is the same as the original,
               hence the output_path should not be the same as the file_path!
'''


def resize_image(file_path, output_path, image_scale_width=299, image_scale_height=299):
    # Reads the given image from the given
    image = tf.io.read_file(file_path)
    # Converts the given image into a numerical Ten
    image = tf.image.decode_png(image, channels=3)
    # Converting the color channels to values between 0-1 (instead of 0-255)
    image = tf.image.convert_image_dtype(image, tf.float32)
    # Resize the image to 299x299 px as default or custom size
    image = tf.image.resize(image, size=[image_scale_width, image_scale_height])
    # Image name
    image_name = get_file_name(file_path)
    # Returns the image in Tensor form
    save_to_path = f'{output_path}/{image_name}.png'
    # Saves the image
    tf.keras.preprocessing.image.save_img(save_to_path, image)
    # Returns the saved to path
    return save_to_path


'''
  // END of method binary_to_grayscale_image
'''
'''
  Nr 11.1
  Method: get_file_name(file_path)
  Args: file_path
  Description: Gets the file name from the file in the given file_path
'''


def get_file_name(file_path):
    # 1. Creates a path
    path = Path(file_path)
    # 2. Gets the file name and removes the file extendsion from the path
    file_name = path.name.replace(path.suffix, '')
    # 3. Returns the file_name
    return file_name


'''
  // End of method get_file_name
'''
'''
  Nr 12
  Method: resize_images(file_path, output_path, image_scale_width=299, image_scale_height=299)
  Args: file_path, output_path, image_scale_width=299, image_scale_height=299
  Description: Resizes the images in the given array input_paths, to the folder output_path.
               The default image size is 299 x 299, but can be specified in image_scale_width and image_scale_height.
               The resized image name is the same as the original image, hence input_paths and output_path
               should not be the same
'''


def resize_images(input_paths, output_path, image_scale_width=299, image_scale_height=299):
    # Gets all the image paths
    images_paths = get_all_files(input_paths, '.png')
    # Index
    index = 0
    # Resizes all the images
    for image_path in images_paths:
        # Increment
        index += 1
        # Scales the images
        resize_image(file_path=image_path, output_path=output_path, image_scale_width=image_scale_width,
                     image_scale_height=image_scale_height)
        # Prints progressbar in console
        show_progress_bar(index, len(images_paths))


'''
  // End of method resize_images
'''
'''
  Nr 12.1
  Method: show_progress_bar(index, length)
  Args: index, length
  Description: Creates a progress bar in the console to show the progress of a loop
'''


def show_progress_bar(index, length):
    # Carriage return
    # (resets the cursor to the beginning of the line / write over what was the previously on the line)
    sys.stdout.write('\r')
    # Index
    progress = (index + 1) / length
    # Adding index and length to the print
    sys.stdout.write(f'{index + 1}/{length} ')
    # Writing the percentages
    sys.stdout.write('[%-30s] %d%%' % ('=' * int(30 * progress), 100 * progress))
    # Clears the stdout
    sys.stdout.flush()


'''
  // End of method
'''
'''
  Nr 13.
  Method: read_virus_total_reports_to_detect_packers(path, database_table)
  Args: path, database_table
  Description: Reads the virus total reports from the given path,
               and extracts the PEiD and TrID information.
               Here only the PEiD signature is added to the database_table.
'''


def read_virus_total_reports_to_detect_packers(path, database_table):
    # Get the JSON files in the given path
    json_files = get_all_files(path, '.json')
    count = 0
    # Loop counter
    index = 0
    # json_files length
    length = len(json_files)
    for json_file_name in json_files:
        # identifier_array contains [PEiD,TrID]
        identifier_array = (extract_packer_identifier_from_json_file(f'{json_file_name}'))
        # If PEiD signature detected
        if identifier_array[0]:
            count += 1
            # Gets the name of the file, who is the file_hash
            file_hash = json_file_name.replace(f'{path}/', '').replace('.json', '')
            # Gets the packer name
            packer_name = identifier_array[0]
            # Inserts the result to the DB
            database_table(file_hash, packer_name)

        # Creates a progressbar in the console
        show_progress_bar(index, length)
        # Increments the index by one
        index += 1


'''
  // End of method read_virus_total_reports_to_detect_packers
'''
'''
    Nr 13.1 
    Method: extract_file_hash_from_json_file(file_path)
    Args: file_path
    Description: Extracts the MD5 and SHA-256 hash from a JSON file
'''
def extract_file_hash_from_json_file(file_path):
    # Reads the JSON file
    json_file = read_json_file(file_path)
    # Return values MD5 and SHA-256
    hash_back = ['', '']
    # Looping through the keys in the JSON file
    for key in json_file:
        # If key matches additional_info
        if key == 'md5':
            # Get the MD5 hash
            md5_hash = json_file[key]
            hash_back[0] = md5_hash
        elif key == 'sha256':
            # Gets the SHA-256 hash
            sha256_hash = json_file[key]
            hash_back[1] = sha256_hash
    # Returns the found values
    return hash_back
'''
    // End of method extract_file_hash_from_json_file
'''
'''
  Nr 13.2
  Method: extract_packer_identifier_from_json_file(file_path)
  Args: file_path
  Description: Extracts the PEiD and TrID if found in the given file_path
'''


def extract_packer_identifier_from_json_file(file_path):
    # PEiD
    peid_detected_packers = ""
    # TrID
    trid_detected_packers = ""
    # Get the JSON file
    data = read_json_file(file_path)
    # Looping through the keys in the JSON file
    for key in data:
        # If key matches additional_info
        if key == 'additional_info':
            # Get the additional_info
            additional_info = data[key]
            # Looping through the keys in the additional_info
            for key_additional_info in additional_info:
                # PEiD
                if key_additional_info == 'peid':
                    # Get the PEiD detected packer name/s
                    peid_detected_packers = additional_info[key_additional_info]
                # TrID
                if key_additional_info == 'trid':
                    # Get the TrID detected packer name/s
                    trid_detected_packers = additional_info[key_additional_info]
    # Return
    return [peid_detected_packers, trid_detected_packers]


'''
  // End of method extract_packer_identifier_from_json_file
'''
'''
  Nr 13.3
  Method: read_json_file(file_path)
  Args: file_path
  Description: Reads the given JSON file from the file_path
'''


def read_json_file(file_path):
    # Reads the file
    with open(file_path) as file:
        data = json.load(file)
    # Return
    return data


'''
  // End of method read_json_file
'''
'''
  Nr 14
  Method: create_data_batch(image_file_paths, labels=None, batch_size=32, data_type=1)
  Args: image_file_paths, labels=None, batch_size=32, data_type=1
  Description: Creates a data batch from the given image_file_paths, optional labels, batch_size and data_type.
               data_type = 1 is the default value, meaning that we are going to the else statement, 
                             and creating training data sets
               data_type = 2 is the else if statement, meaning that we are creating validation data sets
               data_type = 3 is the if statement, meaning that we are creating test data sets
'''


def create_data_batch(image_file_paths, labels=None, batch_size=32, data_type=1):
    # Test dataset don't have labels
    if data_type == 3:  # Test
        #
        data = tf.data.Dataset.from_tensor_slices((tf.constant(image_file_paths)))
        #
        data_batch = data.map(preprocess_image).batch(batch_size)
        return data_batch
    elif data_type == 2:  # Validation
        #
        data = tf.data.Dataset.from_tensor_slices((tf.constant(image_file_paths), tf.constant(labels)))
        #
        data_batch = data.map(image_and_label).batch(batch_size)
        return data_batch
    else:  # Training
        #
        data = tf.data.Dataset.from_tensor_slices((tf.constant(image_file_paths), tf.constant(labels)))
        #
        data = data.shuffle(buffer_size=len(image_file_paths))
        #
        data = data.map(image_and_label)
        #
        data_batch = data.batch(batch_size)
        return data_batch


'''
  // End of method
'''
'''
  Nr 14.1
  Method: preprocess_image(image_file_path, img_width=299, img_height=299)
  Args: image_file_path, img_width=299, img_height=299
  Description: Scales the image from the given image_file_path default to 299 x 299, 
               but alternatively img_width and img_height can also be applied. 
'''


def preprocess_image(image_file_path, img_width=299, img_height=299):
    # Reads the given image from the given file path
    image = tf.io.read_file(image_file_path)
    # Converts the given image into a numerical Tensor (Gray scaled image channels = 1)
    image = tf.image.decode_png(image, channels=3)
    # Converting the color channels to values between 0-1 (instead of 0-255)
    image = tf.image.convert_image_dtype(image, tf.float32)
    # Resize the image to e.g 299x299 px
    image = tf.image.resize(image, size=[img_width, img_height])
    # Returns the image in Tensor form
    return image


'''
  // End of method preprocess_image
'''
'''
  Nr 14.2
  Method: image_and_label(image_file_path, label)
  Args: label_array
  Description: Creates boolean labels e.g. 0 or 1 from a label_array
'''


# Creates an array with an image and a label
def image_and_label(image_file_path, label):
    # Preprocesses the image
    image = preprocess_image(image_file_path)
    # Returns the image and label
    return image, label


'''
  // End of method
'''
'''
  Nr 14.3
  Method: create_boolean_labels(label_array)
  Args: label_array
  Description: Creates boolean labels e.g. 0 or 1 from a label_array
'''


def create_boolean_labels(label_array):
    # Labels becomes either 0 or 1 (benign or malicious)
    labels = LabelEncoder().fit_transform(label_array).reshape(-1, 1)
    return labels
    # Converts the 0 or 1 labels to an array
    #return OneHotEncoder().fit_transform(labels).toarray()


'''
  // End of method create_boolean_labels
'''
'''
  Nr 15
  Method: k_fold(image_paths, boolean_labels, n_split=10)
  Args: image_paths, boolean_labels, n_split=10
  Description: Takes an array of image_paths and boolean_labels to
               split the dataset in n_split=10 as default K-Folds.
'''


def k_fold(image_paths, boolean_labels, n_split=10, shuffle=True):
    # Creates an array to holde the training data sets
    k_fold_training_sets = []
    # Creates an array to holde the validation data sets
    k_fold_validation_sets = []
    # K-fold
    for train_index, val_index in KFold(n_split, shuffle=shuffle).split(image_paths):
        # Gets the training samples and labels
        training_set_paths = [image_paths[i] for i in train_index]
        training_set_labels = np.array([boolean_labels[i] for i in train_index])
        training_set = [training_set_paths, training_set_labels]
        k_fold_training_sets.append(training_set)  # Add the dataset to the array

        # Gets the validation samples and labels
        validation_set_paths = [image_paths[i] for i in val_index]
        validation_set_labels = np.array([boolean_labels[i] for i in val_index])
        validation_set = [validation_set_paths, validation_set_labels]
        k_fold_validation_sets.append(validation_set)  # Add the dataset to the array

    # Returns the training and validation set
    return [k_fold_training_sets, k_fold_validation_sets]


'''
  // End of method
'''
'''
  Nr 16
  Method: stratified_k_fold(image_paths, boolean_labels, n_split=10)
  Args: image_paths, labels, boolean_labels, n_split=10, shuffle=True
  Description: Takes an array of image_paths, labels and boolean_labels to
               split the dataset in n_split=10 as default K-Folds,
               but keeping the data distribution in the dataset.
               The dataset is also shuffled by default shuffle=True 
'''


def stratified_k_fold(image_paths, labels, boolean_labels, n_split=10, shuffle=True):
    # Creates an array to holde the training data sets
    k_fold_training_sets = []
    # Creates an array to holde the validation data sets
    k_fold_validation_sets = []
    # StratifiedKFold
    for train_index, val_index in StratifiedKFold(n_splits=n_split, shuffle=shuffle).split(image_paths, labels):
        # Gets the training samples and labels
        training_set_paths = [image_paths[i] for i in train_index]
        training_set_labels = np.array([boolean_labels[i] for i in train_index])
        training_set = [training_set_paths, training_set_labels]
        k_fold_training_sets.append(training_set)  # Add the dataset to the array

        # Gets the validation samples and labels
        validation_set_paths = [image_paths[i] for i in val_index]
        validation_set_labels = np.array([boolean_labels[i] for i in val_index])
        validation_set = [validation_set_paths, validation_set_labels]
        k_fold_validation_sets.append(validation_set)  # Add the dataset to the array

    # Returns the training and validation set
    return [k_fold_training_sets, k_fold_validation_sets]


'''
  // End of method
'''
'''
  Nr 17
  Method: preprocess_dataset(benign_files_path, malicious_files_path, benign_images_path, malicious_images_path,
                       benign_images_resized_path, malicious_images_resized_path, virus_total_reports_file_path,
                       hash_out, image_scale_width, image_scale_height, database)
  Args: benign_files_path, malicious_files_path, benign_images_path, malicious_images_path,
                       benign_images_resized_path, malicious_images_resized_path, virus_total_reports_file_path,
                       hash_out, image_scale_width, image_scale_height, database
  Description: Preprocess the dataset
'''


def preprocess_dataset(benign_files_path, malicious_files_path, benign_images_path, malicious_images_path,
                       benign_images_resized_path, malicious_images_resized_path, virus_total_reports_file_path,
                       hash_out, image_scale_width, image_scale_height, database):
    # 1. Preproccess the beingn set
    print('1 of 3: Preprocesses the benign set:')
    preprocess_exe_files(benign_files_path, benign_images_path, benign_images_resized_path, hash_out,
                         image_scale_width, image_scale_height, database)
    # 2. Preproccess the malicous set
    print('\n2 of 3: Preprocesses the malicious set:')
    preprocess_exe_files(malicious_files_path, malicious_images_path, malicious_images_resized_path, hash_out,
                         image_scale_width, image_scale_height, database)
    # 3. Preprocess the virus total reports
    print('\n3 of 3: Preprocesses the virus total reports:')
    read_virus_total_reports_to_detect_packers(virus_total_reports_file_path,
                                               database.insert_into_table_virus_total_and_virus_total_packer_cryptor_compiler)


'''
  // End of method preprocess_dataset
'''
'''
  Nr 18
  Method: preprocess_exe_files(exe_file_path, output_image_path, output_resized_image_path, hash_out,
                         image_scale_width, image_scale_height, database)
  Args: exe_file_path, output_image_path, output_resized_image_path, hash_out,
                         image_scale_width, image_scale_height, database
  Description: Preprocess the dataset and creates images from the exe files
'''


def preprocess_exe_files(exe_file_path, output_image_path, output_resized_image_path, hash_out,
                         image_scale_width, image_scale_height, database):
    # 1. Get all the files in the exe_file_path
    exe_file_paths = get_all_exe_files_in_directory(exe_file_path)
    # Loop counter
    index = 0
    # exe file path length
    length = len(exe_file_paths)
    # 2. Looping through the exe files
    for exe_path in exe_file_paths:
        # Sample
        # 2.1 Calculates the file hash from the given file
        file_hash = calculate_hash(exe_path, hash_out)
        # 2.2 Calculates the file entropy from the given file
        file_entropy = calculate_entropy(exe_path)
        # 2.3 Converts the image
        image_file_path = binary_to_grayscale_image(exe_path, output_image_path, hash_out)
        # 2.4 Calculates the image_file_hash
        image_file_hash = calculate_hash(image_file_path, hash_out)
        # 2.5 Resize the image
        resized_image_file_path = resize_image(image_file_path, output_resized_image_path,
                                               image_scale_width, image_scale_height)
        # 2.6 Calculates the resized_image_file_hash
        resized_image_file_hash = calculate_hash(resized_image_file_path, hash_out)
        # 2.7 Inserts the sample into the sample table
        database.insert_into_table_sample(file_hash, image_file_hash, resized_image_file_hash, file_entropy)
        # 2.8 Gets the sample_id
        sample_id = database.select_sample_id_from_table_sample(file_hash)
        # File type
        if 'benign' in exe_file_path:
            # 2.9 Gets the file_type_id
            file_type_id = database.select_file_type_id_from_table_file_type('Benign')
            # 2.10 Inserts the sample_id and file_type_id into the table file_type
            database.insert_into_table_sample_file_type(sample_id, file_type_id)
        elif 'malicious' in exe_file_path:
            # 2.9 Gets the file_type_id
            file_type_id = database.select_file_type_id_from_table_file_type('Malicious')
            # 2.10 Inserts the sample_id and file_type_id into the table file_type
            database.insert_into_table_sample_file_type(sample_id, file_type_id)

        # CPU architecture
        # 2.11 Gets the cpu architecture of the given file
        cpu_architecture = is_exe_file(exe_path)[1]
        # 2.12 Gets the cpu_architecture_id from the table cpu_architecture
        cpu_architecture_id = database.select_cpu_architecture_id_from_table_cpu_architecture(cpu_architecture)
        # 2.13 Inserts the sample_id and cpu_architecture_id into the table sample_cpu_architecture_id
        database.insert_into_table_sample_cpu_architecture(sample_id, cpu_architecture_id)
        # Creates a progressbar in the console
        show_progress_bar(index, length)
        # Increases the index by one
        index += 1


'''
  // End of method preprocess_exe_files
'''
'''
  Nr 19
  Method: preprocess_exe_files(exe_file_path, output_image_path, output_resized_image_path, hash_out,
                         image_scale_width, image_scale_height, database)
  Args: exe_file_path, output_image_path, output_resized_image_path, hash_out,
                         image_scale_width, image_scale_height, database
  Description: Preprocess the dataset and creates images from the exe files
'''


def create_models(image_paths, labels, boolean_labels, feature_extractor_model, n_split, shuffle, s_k_fold,
                  results_path, database, experiment_id):
    #

    # 1. Creates an array to hold the ML models
    ml_models = []
    # 2. Creats an array to hold the training and validation sets
    k_fold_training_sets = []
    k_fold_validation_sets = []
    # 3. Splitt the dataset by using stratified k-fold as default or k-fold
    if s_k_fold:
        print('Stratified K-fold')
        k_fold_training_sets, k_fold_validation_sets = stratified_k_fold(image_paths, labels, boolean_labels, n_split,
                                                                         shuffle)
    else:
        print('K-fold')
        k_fold_training_sets, k_fold_validation_sets = k_fold(image_paths, boolean_labels, n_split, shuffle)

    # Path to save the ML-models
    path_to_save_ml = f'{results_path}/ML-model-{timestamp()}'
    # 4. Training the models
    for index in range(n_split):
        # Printing create ML
        print(f'ML model: {index + 1}')
        # 4.1 Creates an ML model
        model = Transfer_Learning_Model(feature_extractor_model)
        # Creates the model path
        model_path = f'{path_to_save_ml}-{index + 1}'
        # Creates the model name
        model_name = get_file_name(f'{model_path}.h5')
        # Inserts the model name into the table transfer_learning_model
        # name, file_hash, epochs_top_layer, top_layer_loss, top_layer_binary_accuracy
        # epochs_fine_tune_layer, fine_tune_learning_rate, fine_tune_loss, fine_tune_binary_accuracy
        database.insert_into_table_transfer_learning_model(model_name, 'NULL', 'NULL', 'NULL', 'NULL',
                                                           'NULL', 'NULL', 'NULL', 'NULL')
        # Gets the transfer_learning_model_id from the table transfer_learning_model
        transfer_learning_model_id = database.select_transfer_learning_model_id_from_table_transfer_learning_model(
            model_name)
        # Inserts the experiment_id and transfer_learning_model_id into the table experiment_transfer_learning_model
        database.insert_into_table_experiment_transfer_learning_model(experiment_id, transfer_learning_model_id)
        # 4.2 Trains the ML model
        # Prints the model that is beeing trained
        print(f'Training model: {index + 1}')
        # Gets the trainingset
        t_set = k_fold_training_sets[index]
        # Gets the trainingset paths
        t_set_paths = t_set[0]
        # Gets the traingset boolean labels
        t_set_labels = t_set[1]
        # Creates the trainingset
        train_dataset = create_data_batch(t_set_paths, t_set_labels)  # , batch_size=1)
        # Gets the validationset
        v_set = k_fold_validation_sets[index]
        # Gets the validationset paths
        v_set_paths = v_set[0]
        # Gets the validationset labels
        v_set_labels = v_set[1]
        # Creates the trainingset
        val_dataset = create_data_batch(v_set_paths, v_set_labels)  # , batch_size=1)
        # Creates the test dataset
        test_dataset = create_data_batch(v_set_paths, data_type=3)
        # Prints training top layer
        print(f'  Training top layer')
        # Trains the model
        results = model.train(train_dataset=train_dataset, val_dataset=val_dataset,
                              test_dataset=test_dataset)
        # Gets the history
        # history = results[0]
        # epochs_top_layer_loss = history[0]
        # epochs_top_layer_binary_accuracy = history[1]
        # Gets the evaluation
        evaluation = results[1]
        top_layer_loss = evaluation[0]
        top_layer_binary_accuracy = evaluation[1]
        # Get the predictions
        predictions = results[2]
        # Index
        index = 0
        # Length
        length = len(v_set_paths)
        print('Saving the validation set to the database:')
        # Looping through the validation set paths
        for v_set_path in v_set_paths:
            # Gets the file hash from the path
            file_hash = get_file_name(v_set_path)
            # Gets the sample_id
            sample_id = database.select_sample_id_from_table_sample(file_hash)
            # Get the predictions
            prediction = predictions[index]
            #benign_percentage = round_two_decimals(prediction[0])
            #malicious_percentage = round_two_decimals(prediction[1])
            benign_percentage = 0
            malicious_percentage = round_two_decimals(prediction[0])
            #print(f'Benign: {benign_percentage} Malicious{malicious_percentage}')
            # experiment_id, transfer_learning_model_id, sample_id, benign_percentage, malicious_percentage
            database.insert_into_table_experiment_results(experiment_id, transfer_learning_model_id, sample_id,
                                                          benign_percentage, malicious_percentage)
            # Inserts the validation sample to the table transfer_learning_model_val_samples
            database.insert_into_table_transfer_learning_model_val_samples(transfer_learning_model_id, sample_id)
            # Creates a progressbar in the console
            show_progress_bar(index, length)
            # Updates the index by one
            index += 1

        print('\n')
        # Index
        index = 0
        # Length
        length = len(t_set_paths)
        print('Saving the training set to the database:')
        # Looping through the training set paths
        for t_set_path in t_set_paths:
            # Gets the file hash from the path
            file_hash = get_file_name(t_set_path)
            # Gets the sample_id
            sample_id = database.select_sample_id_from_table_sample(file_hash)
            # Inserts the training sample to the table transfer_learning_model_val_samples
            database.insert_into_table_transfer_learning_model_train_samples(transfer_learning_model_id, sample_id)
            # Creates a progressbar in the console
            show_progress_bar(index, length)
            # Increments the index by one
            index += 1

        print('\n')
        # 4.x Saves the model
        model.save_model(model_path)
        # Calculates the entropy of the
        model_hash = calculate_hash(f'{model_path}.h5', 'MD5')
        # UPDATE THE transfer_learning_model table
        # transfer_learning_model_id, name, file_hash, epochs_top_layer, top_layer_loss, top_layer_binary_accuracy
        # epochs_fine_tune_layer, fine_tune_learning_rate, fine_tune_loss, fine_tune_binary_accuracy
        database.update_table_transfer_learning_model(transfer_learning_model_id, model_name, model_hash,
                                                      'NULL', top_layer_loss, top_layer_binary_accuracy,
                                                      'NULL', 'NULL',
                                                      'NULL', 'NULL')


'''
  // End of method 
'''
'''
  
'''


def create_dataset(images_benign, images_malicious, feature_extractor_model, n_split, shuffle, stratified_k_fold,
                   results_path, database, experiment_id):
    # Array holding the images
    image_paths = []
    # Array holding the labels for the images
    labels = []
    # Load the benign images
    benign_images = get_all_files(images_benign, '.png')
    # Load the malicious images
    malicious_images = get_all_files(images_malicious, '.png')
    # Create the labels for the benign set and add the images to the image array
    for benign_image in benign_images:
        labels.append('Benign')
        image_paths.append(benign_image)
    # Create the labels for the malicious set and add the images to the image array
    for malicious_image in malicious_images:
        labels.append('Malicious')
        image_paths.append(malicious_image)

    # Create boolean labels
    boolean_labels = np.array(create_boolean_labels(labels))

    # Create the models
    create_models(image_paths, labels, boolean_labels, feature_extractor_model, n_split, shuffle, stratified_k_fold,
                  results_path, database, experiment_id)


'''
  // End of method 
'''
'''
  Nr xx
  Method: pack_files_in_path_with_upx(path)
  Args: path
  Description: Packs all the files in the given path with upx
  Requirement: UPX must be installed
'''


def pack_files_in_path_with_upx(path):
    # Creates the start timestamp
    start = timestamp()
    print(f'Packing started: {start}')
    # Get all .exe files in the given path
    file_paths = get_all_exe_files_in_directory(path)
    # Loop counter
    index = 0
    # file_paths length
    length = len(file_paths)
    # Error message array
    error_messages = []
    for file_path in file_paths:
        # Pack the file
        # Returns [upx, file_path, exception_type, exception_message]
        error_message = pack_exe_with_upx(file_path)
        # Appends the error message to the array
        if error_message:
            error_messages.append(error_message)

        # Creates a progressbar in the console
        show_progress_bar(index, length)
        # Increments the index by one
        index += 1
    # Prints the error messages
    error_messages.sort()
    for message in error_messages:
        print(message)
    # Creates the end timestamp
    end = timestamp()
    print(f'Packing ended: {end}')


'''
  // End of method pack_files_in_path_with_upx(path)
'''
'''
  Nr xx.1
  Method: pack_exe_with_upx(file_path)
  Args: file_path
  Description: Packs the given file with UPX
  Requirement: UPX must be installed
'''


def pack_exe_with_upx(file_path):
    try:
        pack_file = subprocess.run(f'upx {file_path}', shell=True, check=True)
    except subprocess.CalledProcessError as e:
        print(e)
        # Gets the error message
        #message = str(e.)
        # Splits the error message
        #error_message = message.split(':')
        # Returns [upx, file_path, exception_type, exception_message]
        return str(e)





'''
  // End of method
'''
'''
  Nr xx
  Method:
  Args: 
  Description: 
'''
def preprocess_packed_files(exe_file_path, output_image_path, output_resized_image_path, hash_out,
                         image_scale_width, image_scale_height, database):
    start = timestamp()
    print(f'Preproccessing packed files started: {start}')
    # 1. Preprocess the ece files
    preprocess_exe_files(exe_file_path, output_image_path, output_resized_image_path, hash_out,
                         image_scale_width, image_scale_height, database)
    # 2. Inserts the packer name to the database
    packer_name = 'UPX 3.96 Markus Oberhumer, Laszlo Molnar & John Reiser Jan 23rd 2020'
    # 3. Get all the files
    files = get_all_exe_files_in_directory(exe_file_path)
    # Index
    index = 0
    # Number of files
    length = len(files)
    for file_path in files:
        # 1. Create a hash of the file
        file_hash = calculate_hash(file_path, hash_out)
        # Inserts the packer and sample name into the database
        database.insert_into_table_virus_total_and_virus_total_packer_cryptor_compiler(file_hash, packer_name)
        # Shows a progressbar
        show_progress_bar(index, length)
        # Increment the index
        index += 1
    # End
    end = timestamp()
    print(f'Preproccessing packed files elapsed:  {end-start}')
    print(f'Preproccessing packed files ended: {end}')
'''
  // End of method
'''
'''
  Nr xx
  Method:
  Args: 
  Description: 
'''

def copy(file_path, input_path, output_path):
    # Reads the given file
    with open(file_path) as file:
        lines_in_file = file.readlines()
    # Index
    index = 0
    # Length
    length = len(lines_in_file)
    # File counter
    counter = 0
    # Duplicated files
    duplicated_files = 0
    # Looping line by line
    for line in lines_in_file:
        # Gets the file name
        file_name = line.rstrip()
        # If the file exists e.g. there are duplicates in the set, skip that file
        if os.path.exists(f'{output_path}/{file_name}'):
            duplicated_files += 1
        else:
            # Copy file
            copyfile(f'{input_path}/{file_name}', f'{output_path}/{file_name}')
            counter += 1
        # Draws a progressbar
        show_progress_bar(index, length)
        # Increment the index
        index += 1
    # Print
    print(f'Information: Found {length} files, {duplicated_files} where duplicated and '
          f'{counter} where unique and therefore copied to path: {output_path}')


'''
counter = 0
    duplicated_files = 0
    for src in files_array:
        # Create a hash as a unique file_name SHA-256 as default or MD5
        file_name = src
        # If the file exists e.g. there are duplicates in the set, skip that file
        if os.path.exists(f'{destination}/{file_name}'):
            duplicated_files += 1
        else:
            # Copy file
            copyfile(f'{path}/{file_name}', f'{destination}/{file_name}')
            # Delete file
            os.remove(f'{path}/{file_name}')
            counter += 1
    print(f'Information: Found {len(files_array)} files, {duplicated_files} where duplicated and '
          f'{counter} where unique and therefore copied to path: {destination}')
'''
'''
  // End of method
'''
'''
  Nr xx
  Method: show_progress_bar(index, length)
  Args: index, length
  Description: Creates a progressbar in the console
'''
def verify_our_packer(file_path, experiment_id, db):
    # Reads the given file
    with open(file_path) as file:
        lines_in_file = file.readlines()

    equal_values = []
    not_equal_values = []
    close_equals = []
    for line in lines_in_file:
        temp_line = line.split(' ')
        original_file_hash = temp_line[0]
        packed_file_hash = temp_line[1].strip()
        # 1. Get the Sample ID from the file_hash
        original_file_sample_id = db.select_sample_id_from_table_sample(original_file_hash)
        packed_file_sample_id = db.select_sample_id_from_table_sample(packed_file_hash)
        print(f'{original_file_sample_id} {packed_file_sample_id}')
        # 2. Get the benign and malicious percentage of the original sample
        original_percentage = db.select_benign_and_malicious_percentage_from_table_experiment_results(original_file_sample_id, experiment_id)
        original_percentage_tuplet = original_percentage[0]
        original_percentage_benign = original_percentage_tuplet[0]  # Benign percentage
        original_percentage_malicious = original_percentage_tuplet[1]  # Malicious percentage
        packed_percentage = db.select_benign_and_malicious_percentage_from_table_experiment_results(packed_file_sample_id, experiment_id)
        packed_percentage_tuplet = packed_percentage[0]
        packed_percentage_benign = packed_percentage_tuplet[0]
        packed_percentage_malicious = packed_percentage_tuplet[1]
        print(f'{original_percentage} {packed_percentage}')

        print(f'TEST {original_percentage_benign} {original_percentage_malicious} {packed_percentage_benign} {packed_percentage_malicious}')
        # 4. Get the benign and malicious percentage of the UPX 3.96 sample
        if original_percentage == packed_percentage:
            equal_values.append([original_file_sample_id, original_percentage, packed_file_sample_id, packed_percentage])
        else:
            not_equal_values.append(
                [original_file_sample_id, original_percentage, packed_file_sample_id, packed_percentage])
            # Sample is close
            if original_percentage_benign > packed_percentage_benign:
                r1 = original_percentage_benign - packed_percentage_benign
            elif original_percentage_benign < packed_percentage_benign:
                r1 = packed_percentage_benign - original_percentage_benign

            if original_percentage_malicious > packed_percentage_malicious:
                r2 = original_percentage_malicious - packed_percentage_malicious
            elif original_percentage_malicious < packed_percentage_malicious:
                r2 = packed_percentage_malicious - original_percentage_malicious

            if 0.02 > r1 and 0.02 > r2:
                close_equals.append(
                [original_file_sample_id, original_percentage, packed_file_sample_id, packed_percentage])
        # 5. Check if they are equal
        print(f'Equals = {len(equal_values)} NOT = {len(not_equal_values)} Close = {len(close_equals)}')
'''
  // End of method
'''
'''
  Nr xx
  Method: show_progress_bar(index, length)
  Args: index, length
  Description: Creates a progressbar in the console
'''


def show_progress_bar(index, length):
    # Carriage return
    # (resets the cursor to the beginning of the line / write over what was the previously on the line)
    sys.stdout.write('\r')
    # Index
    progress = (index + 1) / length
    # Adding index and length to the print
    sys.stdout.write(f'{index + 1}/{length} ')
    # Writing the percentages
    sys.stdout.write('[%-30s] %d%%' % ('=' * int(30 * progress), 100 * progress))
    # Clears the stdout
    sys.stdout.flush()


'''
  // End of method
'''
'''
  Nr xx
  Method: 
  Args: 
  Description: Creates 
'''
def split_dataset(image_paths, boolean_labels, test_size=0.3): # Default 30 % test size, hence 70 % val
    # Splits the dataset
    X_train, X_val, y_train, y_val = train_test_split(image_paths, boolean_labels, test_size=test_size)
    # Returns the training and validation sets
    return [X_train, X_val, y_train, y_val]
'''
  // End of method
'''
'''
def stratified_k_fold(image_paths, labels, boolean_labels, n_split=10, shuffle=True):
    # Creates an array to holde the training data sets
    k_fold_training_sets = []
    # Creates an array to holde the validation data sets
    k_fold_validation_sets = []
    # StratifiedKFold
    for train_index, val_index in StratifiedKFold(n_splits=n_split, shuffle=shuffle).split(image_paths, labels):
        # Gets the training samples and labels
        training_set_paths = [image_paths[i] for i in train_index]
        training_set_labels = np.array([boolean_labels[i] for i in train_index])
        training_set = [training_set_paths, training_set_labels]
        k_fold_training_sets.append(training_set)  # Add the dataset to the array

        # Gets the validation samples and labels
        validation_set_paths = [image_paths[i] for i in val_index]
        validation_set_labels = np.array([boolean_labels[i] for i in val_index])
        validation_set = [validation_set_paths, validation_set_labels]
        k_fold_validation_sets.append(validation_set)  # Add the dataset to the array

    # Returns the training and validation set
    return [k_fold_training_sets, k_fold_validation_sets]

'''