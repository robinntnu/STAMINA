'''

'''
# Setup
from sql import Database
import library as lb
import os
from shutil import copyfile

# Preprocesses the benign and malicious files,
# converting them to images and reads the VirusTotal reports
# if True
PREPROCESS_DATA_FLAG = False
'''
  Dataset file structure:
  dataset_x
  ........../benign_files
  ........./malicious_files
  ........./images
  ................/benign
  ................/malicious
  ........./resized_images
  ......................../benign
  ......................../malicious
  ........./results
  ................./dd.MM.yyyy
  ........./VirusTotal_reports
'''
DATASET_PATH = '/Users/reveng/Downloads/data_set_1'#'/Volumes/Malware/dataset_2'  # '/Users/reveng/Downloads/data_set_1'  #
BENIGN_FILES_PATH = DATASET_PATH + '/benign_files'
MALICIOUS_FILES_PATH = DATASET_PATH + '/malicious_files'
IMAGES_PATH = DATASET_PATH + '/images'
BENIGN_IMAGES_PATH = IMAGES_PATH + '/benign'
MALICIOUS_IMAGES_PATH = IMAGES_PATH + '/malicious'
RESIZED_IMAGES_PATH = DATASET_PATH + '/resized_images'
BENIGN_IMAGES_RESIZED_PATH = RESIZED_IMAGES_PATH + '/benign'
MALICIOUS_IMAGES_RESIZE_PATH = RESIZED_IMAGES_PATH + '/malicious'
RESULTS_PATH = DATASET_PATH + '/results'
VIRUSTOTAL_REPORTS_FILE_PATH = DATASET_PATH + '/VirusTotal_reports'

# File hashes of the processed .exe files
FILE_HASH_OUT = 'MD5'
# Image height and width for the ML model images
IMAGE_SCALE_WIDTH = 299
IMAGE_SCALE_HEIGHT = 299
# N-Split
N_SPLIT = 5
# Shuffle
SHUFFLE = True
# Stratified K-fold
STRATIFIED_K_FOLD = True
# Feature extractor model
FEATURE_EXTRACTOR_MODEL = True


# Method for running an experiment
def experiment_1(database):
  # Experiment number 1
  experiment_number = 1
  # Experiment name
  experiment_name = f'Experiment {experiment_number}'
  # Experiment start time
  start = lb.timestamp()
  print(f'Experiment {experiment_number} started: {start}')
  # Inserts the experiment into the database
  database.insert_into_table_experiment(experiment_name, start, 'NULL')
  # Gets the experiment id from the newly created experiment
  experiment_id = database.select_experiment_id_from_table_experiment(experiment_name, start)
  # Run the experiment
  lb.create_dataset(BENIGN_IMAGES_RESIZED_PATH, MALICIOUS_IMAGES_RESIZE_PATH,
                    FEATURE_EXTRACTOR_MODEL, N_SPLIT, SHUFFLE, STRATIFIED_K_FOLD,
                    RESULTS_PATH, database, experiment_id)
  # Experiment end time
  end = lb.timestamp()
  # Updates the end time in the experiment table
  database.update_experiment_end_from_table_experiment(experiment_id, end)
  print(f'Experiment {experiment_number} ended: {start}')
  # Experiment elapsed time
  print(f'Elapsed time: {end - start}')


# Method for running an experiment
def experiment_2(database):
  # Experiment number 2
  experiment_number = 30
  # Experiment name
  experiment_name = f'Experiment {experiment_number}'
  # Experiment start time
  start = lb.timestamp()
  print(f'Experiment {experiment_number} started: {start}')
  # Inserts the experiment into the database
  database.insert_into_table_experiment(experiment_name, start, 'NULL')
  # Gets the experiment id from the newly created experiment
  experiment_id = database.select_experiment_id_from_table_experiment(experiment_name, start)
  #
  FEATURE_EXTRACTOR_MODEL = False
  # Run the experiment
  lb.create_dataset(BENIGN_IMAGES_RESIZED_PATH, MALICIOUS_IMAGES_RESIZE_PATH,
                    FEATURE_EXTRACTOR_MODEL, N_SPLIT, SHUFFLE, STRATIFIED_K_FOLD,
                    RESULTS_PATH, database, experiment_id)
  # Experiment end time
  end = lb.timestamp()
  # Updates the end time in the experiment table
  database.update_experiment_end_from_table_experiment(experiment_id, end)
  print(f'Experiment {experiment_number} ended: {start}')
  # Experiment elapsed time
  print(f'Elapsed time: {end - start}')


# Helper method if the hash_out parameter was set wrong
def read_json_files(path, database_table, hash_out='SHA-256'):
  # Get the JSON files in the given path
  json_files = lb.get_all_files(path, '.json')
  count = 0
  # Loop counter
  index = 0
  # json_files length
  length = len(json_files)
  for json_file_name in json_files:
    # identifier_array contains [PEiD,TrID]
    identifier_array = (lb.extract_packer_identifier_from_json_file(f'{json_file_name}'))
    # If PEiD signature detected
    if identifier_array[0]:
      count += 1
      # Gets the MD5 and SHA-256 hash from the JSON file
      md5_and_sha256_hash = lb.extract_file_hash_from_json_file(json_file_name)
      if hash_out == 'SHA-256':
        file_hash = md5_and_sha256_hash[1]  # Gets the SHA-256 hash
      elif hash_out == 'MD5':
        file_hash = md5_and_sha256_hash[0]  # Gets the MD5 hash
      # Gets the packer name
      packer_name = identifier_array[0]
      # Inserts the result to the DB
      database_table(file_hash.strip(), packer_name)

    # Creates a progressbar in the console
    lb.show_progress_bar(index, length)
    # Increments the index by one
    index += 1


# Helper method if the hash_out parameter was set wrong
def switch_hash_names(path, hash_out='SHA-256'):
  # Get the JSON files in the given path
  exe_files = lb.get_all_exe_files_in_directory(path)
  count = 0
  # Loop counter
  index = 0
  # exe_files length
  length = len(exe_files)
  for exe_file_path in exe_files:
    sha_256 = lb.calculate_hash(f'{exe_file_path}', 'SHA-256')
    md_5 = lb.calculate_hash(f'{exe_file_path}', 'MD5')

    if hash_out == 'SHA-256':
      new_file_name = exe_file_path.replace(md_5, sha_256)
      os.rename(f'{exe_file_path}', f'{new_file_name}')
    elif hash_out == 'MD5':
      new_file_name = exe_file_path.replace(sha_256, md_5)
      os.rename(f'{exe_file_path}', f'{new_file_name}')

    # Creates a progressbar in the console
    lb.show_progress_bar(index, length)
    # Increments the index by one
    index += 1


def copy_files_and_delete_directory(path, files_array, destination):
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


if __name__ == '__main__':
  # 1. Creates the database to store the experiment results, if it does not exists
  db = Database('STAMINA_0')

  # 2. Preprocess the data for analysis, if flag is True
  if PREPROCESS_DATA_FLAG:
    # 3. Preprocess the dataset
    lb.preprocess_dataset(BENIGN_FILES_PATH, MALICIOUS_FILES_PATH, BENIGN_IMAGES_PATH, MALICIOUS_IMAGES_PATH,
                          BENIGN_IMAGES_RESIZED_PATH, MALICIOUS_IMAGES_RESIZE_PATH, VIRUSTOTAL_REPORTS_FILE_PATH,
                          FILE_HASH_OUT, IMAGE_SCALE_WIDTH, IMAGE_SCALE_HEIGHT, db)
  # Experiment 1
  # experiment_1(db)
  # Experiment 2
  experiment_2(db)
  # Closes the database
  db.close()
