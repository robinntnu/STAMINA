'''
  Author: Robin Berg Jønsson
  Created: 23.04.2021
  Last edited:
  Description: This file represents a result database, storing the experiment results
  Methods:
    1.
    2.
    3.
    4.
'''
# Setup
import sqlite3
import os

class Database:
  def __init__(self, db_name):
    # Database name
    self.db_name = f'{db_name}.db'
    # If the database exists open
    if self.exists(self.db_name):
      # Loads the existing database
      self.db = self.open(self.db_name)
      # Creating a cursor to work it the database itself
      self.cursor = self.db.cursor()
    else:  # Else, create it
      # Creates the database
      self.db = self.create(self.db_name)
      # Creating a cursor to work it the database itself
      self.cursor = self.db.cursor()
      # Creates all the tables
      self.create_all_tables()
      # Creates all the views
      self.create_all_views()
      # Inserts the necessary data to the database
      self.insert_default_data()

  # Creates the database, if it does not exists
  def create(self, db_name):
    # Creates the database with the given name
    db = self.open(db_name)
    # Committing the SQL query, creating the db
    db.commit()
    # Returns the open connection
    return db

  # Checking if the database exists
  def exists(self, db_name):
    if os.path.isfile(db_name):
      return True
    return False

  # Helping methods for queries
  def sql_query(self, query, args):
    # Execute the sql_sentence
    self.cursor.execute(query, args)
    # Updates the DB record
    self.db.commit()
    # Gets the SQL query result, if any
    return self.cursor.fetchall()

  # Opens the database
  def open(self, db_name):
    # Opens or creates the database, if it does not exists
    return sqlite3.connect(db_name)

  # Closing the database
  def close(self):
    # Close cursor
    self.cursor.close()
    # Close DB
    self.db.close()

  '''
      Tables
  '''

  # Create the table file_type
  def create_table_file_type(self):
    # SQL query sentence
    query = ('CREATE TABLE IF NOT EXISTS file_type( ' +
             'file_type_id INTEGER PRIMARY KEY, ' +
             'name VARCHAR(9))')
    # Arguments
    args = ()
    # Executes the SQL query
    self.sql_query(query, args)

    # Create the table sample

  def create_table_sample(self):
    # SQL query sentence
    query = ('CREATE TABLE IF NOT EXISTS sample( ' +
             'sample_id INTEGER PRIMARY KEY, ' +
             'original_sample_file_hash VARCHAR(255), ' +
             'image_file_hash VARCHAR(255), ' +
             'scaled_image_file_hash VARCHAR(255), ' +
             'original_file_entropy FLOAT(4,2))')
    # Arguments
    args = ()
    # Executes the SQL query
    self.sql_query(query, args)

  # Create the table sample_file_type
  def create_table_sample_file_type(self):
    # SQL query sentence
    query = ('CREATE TABLE IF NOT EXISTS sample_file_type( ' +
             'sample_id INTEGER, ' +
             'file_type_id INTEGER, ' +
             'FOREIGN KEY (sample_id) REFERENCES sample(sample_id), ' +
             'FOREIGN KEY (file_type_id) REFERENCES file_type(file_type_id))')
    # Arguments
    args = ()
    # Executes the SQL query
    self.sql_query(query, args)

  # Create the table cpu_architecture x86 or x64
  def create_table_cpu_architecture(self):
    # SQL query sentence
    query = ('CREATE TABLE IF NOT EXISTS cpu_architecture( ' +
             'cpu_architecture_id INTEGER PRIMARY KEY, ' +
             'architecture CHAR(3))')
    # Arguments
    args = ()
    # Executes the SQL query
    self.sql_query(query, args)

  # Create the table sample_cpu_architecture
  def create_table_sample_cpu_architecture(self):
    # SQL query sentence
    query = ('CREATE TABLE IF NOT EXISTS sample_cpu_architecture( ' +
             'sample_id INTEGER, ' +
             'cpu_architecture_id INTEGER, ' +
             'FOREIGN KEY (sample_id) REFERENCES sample(sample_id), ' +
             'FOREIGN KEY (cpu_architecture_id) ' +
             'REFERENCES cpu_architecture(cpu_architecture_id))')
    # Arguments
    args = ()
    # Executes the SQL query
    self.sql_query(query, args)

  # Create the table virus_total_packer_cryptor_compiler
  def create_table_virus_total_packer_cryptor_compiler(self):
    # SQL query sentence
    query = ('CREATE TABLE IF NOT EXISTS virus_total_packer_cryptor_compiler( ' +
             'virus_total_packer_cryptor_compiler_id INTEGER PRIMARY KEY, ' +
             'name VARCHAR(255))')
    # Arguments
    args = ()
    # Executes the SQL query
    self.sql_query(query, args)

  # Create the table virus_total
  def create_table_virus_total(self):
    # SQL query sentence
    query = ('CREATE TABLE IF NOT EXISTS virus_total( ' +
             'sample_id INTEGER, ' +
             'virus_total_packer_cryptor_compiler_id INTEGER, ' +
             'FOREIGN KEY (sample_id) REFERENCES sample(sample_id), ' +
             'FOREIGN KEY (virus_total_packer_cryptor_compiler_id) ' +
             'REFERENCES virus_total_packer_cryptor_compiler(virus_total_packer_cryptor_compiler_id))')
    # Arguments
    args = ()
    # Executes the SQL query
    self.sql_query(query, args)

  # Create the table entropy
  def create_table_entropy(self):
    # SQL query sentence
    query = ('CREATE TABLE IF NOT EXISTS entropy( ' +
             'entropy_id INTEGER PRIMARY KEY, ' +
             'name VARCHAR(21), ' +
             'average_entropy FLOAT(4,3))')
    # Arguments
    args = ()
    # Executes the SQL query
    self.sql_query(query, args)

  # Create the table transfer_learning_model
  def create_table_transfer_learning_model(self):
    # SQL query sentence
    query = ('CREATE TABLE IF NOT EXISTS transfer_learning_model( ' +
             'transfer_learning_model_id INTEGER PRIMARY KEY, ' +
             'name VARCHAR(255), ' +
             'file_hash VARCHAR(255), ' +
             'epochs_top_layer INTEGER, ' +
             'top_layer_loss FLOAT(4,2), ' +
             'top_layer_binary_accuracy FLOAT(4,2), ' +
             'epochs_fine_tune_layer INTEGER, ' +
             'fine_tune_learning_rate FLOAT, ' +
             'fine_tune_loss FLOAT(4,2), ' +
             'fine_tune_binary_accuracy FLOAT(4,2))')
    # Arguments
    args = ()
    # Executes the SQL query
    self.sql_query(query, args)

  # Create the table transfer_learning_model_train_samples
  def create_table_transfer_learning_model_train_samples(self):
    # SQL query sentence
    query = ('CREATE TABLE IF NOT EXISTS transfer_learning_model_train_samples( ' +
             'transfer_learning_model_id INTEGER, ' +
             'sample_id INTEGER, ' +
             'FOREIGN KEY (transfer_learning_model_id) REFERENCES transfer_learning_model(transfer_learning_model_id), ' +
             'FOREIGN KEY (sample_id) REFERENCES sample(sample_id))')
    # Arguments
    args = ()
    # Executes the SQL query
    self.sql_query(query, args)

  # Create the table transfer_learning_model_val_samples
  def create_table_transfer_learning_model_val_samples(self):
    # SQL query sentence
    query = ('CREATE TABLE IF NOT EXISTS transfer_learning_model_val_samples( ' +
             'transfer_learning_model_id INTEGER, ' +
             'sample_id INTEGER, ' +
             'FOREIGN KEY (transfer_learning_model_id) REFERENCES transfer_learning_model(transfer_learning_model_id), ' +
             'FOREIGN KEY (sample_id) REFERENCES sample(sample_id))')
    # Arguments
    args = ()
    # Executes the SQL query
    self.sql_query(query, args)

  # Create the table experiment
  def create_table_experiment(self):
    # SQL query sentence
    query = ('CREATE TABLE IF NOT EXISTS experiment( ' +
             'experiment_id INTEGER PRIMARY KEY, ' +
             'name VARCHAR(255), ' +
             'start TIMESTAMP, ' +
             'end TIMESTAMP)')
    # Arguments
    args = ()
    # Executes the SQL query
    self.sql_query(query, args)

  # Create the table experiment_transfer_learning_model
  def create_table_experiment_transfer_learning_model(self):
    # SQL query sentence
    query = ('CREATE TABLE IF NOT EXISTS experiment_transfer_learning_model( ' +
             'experiment_id INTEGER, ' +
             'transfer_learning_model_id INTEGER, ' +
             'FOREIGN KEY (experiment_id) REFERENCES experiment(experiment_id), ' +
             'FOREIGN KEY (transfer_learning_model_id) REFERENCES transfer_learning_model(transfer_learning_model_id))')
    # Arguments
    args = ()
    # Executes the SQL query
    self.sql_query(query, args)

  # Create the table experiment_results
  def create_table_experiment_results(self):
    # SQL query sentence
    query = ('CREATE TABLE IF NOT EXISTS experiment_results( ' +
             'experiment_id INTEGER, ' +
             'transfer_learning_model_id INTEGER, ' +
             'sample_id INTEGER, ' +
             'benign_percentage FLOAT(4, 2), ' +
             'malicious_percentage FLOAT(4, 2), ' +
             'FOREIGN KEY (sample_id) REFERENCES sample(sample_id),' +
             'FOREIGN KEY (experiment_id) REFERENCES experiment(experiment_id), ' +
             'FOREIGN KEY (transfer_learning_model_id) REFERENCES transfer_learning_model(transfer_learning_model_id))')
    # Arguments
    args = ()
    # Executes the SQL query
    self.sql_query(query, args)

  # Create all views
  def create_all_tables(self):
    # Creates the table file_type
    self.create_table_file_type()
    # Creates the table sample
    self.create_table_sample()
    # Creates the table sample_file_type
    self.create_table_sample_file_type()
    # Creates the table create_table_cpu_architecture
    self.create_table_cpu_architecture()
    # Creates the table create_table_sample_cpu_architecture
    self.create_table_sample_cpu_architecture()
    # Creates the table virus_total_packer_cryptor_compiler
    self.create_table_virus_total_packer_cryptor_compiler()
    # Creates the table virus_total
    self.create_table_virus_total()
    # Creates the table table_entropy
    self.create_table_entropy()
    # Creates the table transfer_learning_model
    self.create_table_transfer_learning_model()
    # Creates the table transfer_learning_model_train_samples
    self.create_table_transfer_learning_model_train_samples()
    # Creates the table transfer_learning_model_val_samples
    self.create_table_transfer_learning_model_val_samples()
    # Creates the table experiment
    self.create_table_experiment()
    # Creates the table experiment_transfer_learning_model
    self.create_table_experiment_transfer_learning_model()
    # Creates table experiment_results
    self.create_table_experiment_results()

  '''
      // End of Tables
  '''

  '''
      Views
  '''

  # Creates all the views
  def create_all_views(self):
    print('')

  '''
      // End of Views
  '''

  '''
      Insert Methods
  '''

  # Inserts the file_type name into the table file_type
  def insert_into_table_file_type(self, name):
    # SQL query sentence
    query = ('INSERT INTO file_type' +
             '(file_type_id, name)' +
             'VALUES(NULL, ?)')
    # Arguments
    args = (name,)
    # Executes the SQL query
    self.sql_query(query, args)

  # Inserts the original_sample_file_hash, image_file_hash,
  # scaled_image_file_hash, original_file_entropy into the table file_type
  def insert_into_table_sample(self, original_sample_file_hash,
                                  image_file_hash,
                                  scaled_image_file_hash,
                                  original_file_entropy):
    # SQL query sentence
    query = ('INSERT INTO sample' +
             '(sample_id, original_sample_file_hash, ' +
             'image_file_hash, scaled_image_file_hash, ' +
             'original_file_entropy)' +
             'VALUES(NULL, ?, ?, ?, ?)')
    # Arguments
    args = (original_sample_file_hash, image_file_hash,
            scaled_image_file_hash, original_file_entropy)
    # Executes the SQL query
    self.sql_query(query, args)

  # Inserts the sample_id and file_type_id into the table sample_file_type
  def insert_into_table_sample_file_type(self, sample_id, file_type_id):
    # SQL query sentence
    query = ('INSERT INTO sample_file_type' +
             '(sample_id, file_type_id) ' +
             'VALUES(?, ?)')
    # Arguments
    args = (sample_id, file_type_id)
    # Executes the SQL query
    self.sql_query(query, args)

  # Inserts the sample_id and file_type_id into the table sample_file_type
  def insert_into_table_cpu_architecture(self, architecture):
    # SQL query sentence
    query = ('INSERT INTO cpu_architecture' +
             '(cpu_architecture_id, architecture) ' +
             'VALUES(NULL, ?)')
    # Arguments
    args = (architecture,)
    # Executes the SQL query
    self.sql_query(query, args)

  # Inserts the sample_id and cpu_architecture_id into the table sample_cpu_architecture
  def insert_into_table_sample_cpu_architecture(self, sample_id, cpu_architecture_id):
    # SQL query sentence
    query = ('INSERT INTO sample_cpu_architecture' +
             '(sample_id, cpu_architecture_id) ' +
             'VALUES(?, ?)')
    # Arguments
    args = (sample_id, cpu_architecture_id)
    # Executes the SQL query
    self.sql_query(query, args)

  # Inserts the virus_total_packer_cryptor_compiler_id and
  # name into the table virus_total_packer_cryptor_compiler
  def insert_into_table_virus_total_packer_cryptor_compiler(self, name):
    # SQL query sentence
    query = ('INSERT INTO virus_total_packer_cryptor_compiler' +
             '(virus_total_packer_cryptor_compiler_id, name) ' +
             'VALUES(NULL, ?)')
    # Arguments
    args = (name,)
    # Executes the SQL query
    self.sql_query(query, args)

  # Inserts the sample_id and virus_total_packer_cryptor_compiler_id
  # into the table virus_total
  def insert_into_table_virus_total(self, sample_id,
                                    virus_total_packer_cryptor_compiler_id):
    # SQL query sentence
    query = ('INSERT INTO virus_total' +
             '(sample_id, virus_total_packer_cryptor_compiler_id) ' +
             'VALUES(?, ?)')
    # Arguments
    args = (sample_id, virus_total_packer_cryptor_compiler_id)
    # Executes the SQL query
    self.sql_query(query, args)

  def insert_into_table_virus_total_and_virus_total_packer_cryptor_compiler(self, file_hash, name):
    # 1. See if the packer / cryptor / compiler name exists
    virus_total_packer_cryptor_compiler_id = self.select_virus_total_packer_cryptor_compiler_id_from_table_virus_total_packer_cryptor_compiler(name)
    # 2. Gets the sample_id from the table sample
    sample_id = self.select_sample_id_from_table_sample(file_hash)
    # 3. If the packer / cryptor / compiler name does not exists
    if virus_total_packer_cryptor_compiler_id is None:
      # 3.1 Inserts the packer / cryptor / compiler name
      self.insert_into_table_virus_total_packer_cryptor_compiler(name)
      # 3.2 Gets the virus_total_packer_cryptor_compiler_id again
      virus_total_packer_cryptor_compiler_id = self.select_virus_total_packer_cryptor_compiler_id_from_table_virus_total_packer_cryptor_compiler(name)
      # 3.3 Inserts the sample_id and virus_total_packer_cryptor_compiler_id into the table insert_into_table_virus_total
      self.insert_into_table_virus_total(sample_id, virus_total_packer_cryptor_compiler_id)
    else:
      # 3.3 Inserts the sample_id and virus_total_packer_cryptor_compiler_id into the table insert_into_table_virus_total
      self.insert_into_table_virus_total(sample_id, virus_total_packer_cryptor_compiler_id)

  # Inserts the name into the table entropy
  def insert_into_table_entropy(self, name, average_entropy):
    # SQL query sentence
    query = ('INSERT INTO entropy' +
             '(entropy_id, name, average_entropy) ' +
             'VALUES(NULL, ?, ?)')
    # Arguments
    args = (name, average_entropy)
    # Executes the SQL query
    self.sql_query(query, args)

  # Inserts the name, file_hash, epochs_top_layer, top_layer_loss,
  # into the table transfer_learning_model
  def insert_into_table_transfer_learning_model(self, name, file_hash,
                                                epochs_top_layer,
                                                top_layer_loss,
                                                top_layer_binary_accuracy,
                                                epochs_fine_tune_layer,
                                                fine_tune_learning_rate,
                                                fine_tune_loss,
                                                fine_tune_binary_accuracy):
    # SQL query sentence
    query = ('INSERT INTO transfer_learning_model' +
             '(transfer_learning_model_id, name, ' +
             'file_hash, epochs_top_layer, top_layer_loss, ' +
             'top_layer_binary_accuracy, epochs_fine_tune_layer, ' +
             'fine_tune_learning_rate, fine_tune_loss, ' +
             'fine_tune_binary_accuracy) ' +
             'VALUES(NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?)')
    # Arguments
    args = (name, file_hash, epochs_top_layer, top_layer_loss,
            top_layer_binary_accuracy, epochs_fine_tune_layer,
            fine_tune_learning_rate, fine_tune_loss,
            fine_tune_binary_accuracy)
    # Executes the SQL query
    self.sql_query(query, args)

  # Inserts the transfer_learning_model_id and sample_id
  # into the table transfer_learning_model_train_samples
  def insert_into_table_transfer_learning_model_train_samples(self, transfer_learning_model_id,
                                                              sample_id):
    # SQL query sentence
    query = ('INSERT INTO transfer_learning_model_train_samples' +
             '(transfer_learning_model_id, sample_id) ' +
             'VALUES(?, ?)')
    # Arguments
    args = (transfer_learning_model_id, sample_id)
    # Executes the SQL query
    self.sql_query(query, args)

  # Inserts the transfer_learning_model_id and sample_id
  # into the table transfer_learning_model_val_samples
  def insert_into_table_transfer_learning_model_val_samples(self, transfer_learning_model_id,
                                                            sample_id):
    # SQL query sentence
    query = ('INSERT INTO transfer_learning_model_val_samples' +
             '(transfer_learning_model_id, sample_id) ' +
             'VALUES(?, ?)')
    # Arguments
    args = (transfer_learning_model_id, sample_id)
    # Executes the SQL query
    self.sql_query(query, args)

  # Inserts the name, start and end into the table experiment
  def insert_into_table_experiment(self, name, start, end):
    # SQL query sentence
    query = ('INSERT INTO experiment' +
             '(experiment_id, name, start, end) ' +
             'VALUES(NULL, ?, ?, ?)')
    # Arguments
    args = (name, start, end)
    # Executes the SQL query
    self.sql_query(query, args)

  # Inserts the experiment_id and transfer_learning_model_id
  # into the table experiment_transfer_learning_model
  def insert_into_table_experiment_transfer_learning_model(self, experiment_id,
                                                           transfer_learning_model_id):
    # SQL query sentence
    query = ('INSERT INTO experiment_transfer_learning_model' +
             '(experiment_id, transfer_learning_model_id) ' +
             'VALUES(?, ?)')
    # Arguments
    args = (experiment_id, transfer_learning_model_id)
    # Executes the SQL query
    self.sql_query(query, args)

  # Inserts the experiment_id and transfer_learning_model_id
  # into the table experiment_results
  def insert_into_table_experiment_results(self, experiment_id, transfer_learning_model_id,
                                           sample_id, benign_percentage, malicious_percentage):
    # SQL query sentence
    query = ('INSERT INTO experiment_results' +
             '(experiment_id, transfer_learning_model_id, sample_id, ' +
             'benign_percentage, malicious_percentage) ' +
             'VALUES(?, ?, ?, ?, ?)')
    # Arguments
    args = (experiment_id, transfer_learning_model_id, sample_id,
            benign_percentage, malicious_percentage, )
    # Executes the SQL query
    self.sql_query(query, args)

  # Inserts all the default data
  def insert_default_data(self):
    # Inserts into file_type
    self.insert_into_table_file_type('Benign')
    self.insert_into_table_file_type('Malicious')
    self.insert_into_table_cpu_architecture('x86')
    self.insert_into_table_cpu_architecture('x64')
    self.insert_into_table_entropy('Plain text', 4.347)
    self.insert_into_table_entropy('Native executables', 5.099)
    self.insert_into_table_entropy('Packed executables', 6.801)
    self.insert_into_table_entropy('Encrypted executables', 7.175)

  '''
    // Insert Methods
  '''
  '''
    Select Methods
  '''
  # Helper method
  def get_result_from_query(self, result):
    if result:
      return result[0][0]
    else:
      return None

  # Gets the sample_id from table sample by original_sample_file_hash
  def select_sample_id_from_table_sample(self, original_sample_file_hash):
    # SQL query sentence
    query = ('SELECT sample_id ' +
             'FROM sample ' +
             'WHERE original_sample_file_hash = ?')

    # Arguments
    args = (original_sample_file_hash, )
    # Executes the SQL query
    return self.get_result_from_query(self.sql_query(query, args))

  # Gets all samples from table sample
  def select_all_samples_from_table_sample(self):
    # SQL query sentence
    query = ('SELECT * ' +
             'FROM sample')

    # Arguments
    args = ()
    # Executes the SQL query
    return self.sql_query(query, args)

  # Gets the file_type_id from the table file_type
  def select_file_type_id_from_table_file_type(self, name):
    # SQL query sentence
    query = ('SELECT file_type_id ' +
             'FROM file_type ' +
             'WHERE name = ?')

    # Arguments
    args = (name, )
    # Executes the SQL query
    return self.get_result_from_query(self.sql_query(query, args))

  # Gets the cpu_architecture_id from the table cpu_architecture
  def select_cpu_architecture_id_from_table_cpu_architecture(self, architecture):
    # SQL query sentence
    query = ('SELECT cpu_architecture_id ' +
             'FROM cpu_architecture ' +
             'WHERE architecture = ?')

    # Arguments
    args = (architecture, )
    # Executes the SQL query
    return self.get_result_from_query(self.sql_query(query, args))

  def select_virus_total_packer_cryptor_compiler_id_from_table_virus_total_packer_cryptor_compiler(self, name):
    # SQL query sentence
    query = ('SELECT virus_total_packer_cryptor_compiler_id ' +
             'FROM virus_total_packer_cryptor_compiler ' +
             'WHERE name = ?')

    # Arguments
    args = (name,)
    # Executes the SQL query
    return self.get_result_from_query(self.sql_query(query, args))

  # Gets the experiment id
  def select_experiment_id_from_table_experiment(self, name, start):
    # SQL query sentence
    query = ('SELECT experiment_id ' +
             'FROM experiment ' +
             'WHERE name = ? AND start = ?')

    # Arguments
    args = (name, start)
    # Executes the SQL query
    return self.get_result_from_query(self.sql_query(query, args))

  def select_transfer_learning_model_id_from_table_transfer_learning_model(self, name):
    # SQL query sentence
    query = ('SELECT transfer_learning_model_id ' +
             'FROM transfer_learning_model ' +
             'WHERE name = ?')

    # Arguments
    args = (name,)
    # Executes the SQL query
    return self.get_result_from_query(self.sql_query(query, args))

  # Gets the Datatype_ID from the table Datatype
  def select_entropy_name_from_table_entropy_by_average_entropy(self, file_entropy):
    # SQL query sentence
    query = "SELECT entropy.name FROM entropy ORDER BY ABS(entropy.average_entropy - ?) LIMIT 1"
    # Arguments
    args = (file_entropy,)
    # Executes the SQL query
    return self.get_result_from_query(self.sql_query(query, args))

  # Gets the file_type_id from the table file_type
  def select_benign_and_malicious_percentage_from_table_experiment_results(self, sample_id, experiment_id):
    # SQL query sentence
    query = ('SELECT benign_percentage, malicious_percentage ' +
             'FROM experiment_results ' +
             'WHERE experiment_id = ? ' +
             'AND sample_id = ?')


    # Arguments
    args = (experiment_id, sample_id, )
    # Executes the SQL query
    return self.sql_query(query, args)
  '''
    // End of Select Methods
  '''
  '''
    Update Methods
  '''

  # Updates the end in table experiment
  def update_experiment_end_from_table_experiment(self, experiment_id, end):
    # SQL query sentence
    query = ('UPDATE experiment ' +
             'SET end = ? ' +
             'WHERE experiment_id = ?')

    # Arguments
    args = (end, experiment_id)
    # Executes the SQL query
    return self.get_result_from_query(self.sql_query(query, args))

  # Updates the end in table experiment
  def update_table_transfer_learning_model(self, transfer_learning_model_id, name,
                                           file_hash, epochs_top_layer, top_layer_loss, top_layer_binary_accuracy,
                                           epochs_fine_tune_layer, fine_tune_learning_rate, fine_tune_loss,
                                           fine_tune_binary_accuracy):
    # SQL query sentence
    query = ('UPDATE transfer_learning_model ' +
             'SET name = ?, ' +
             'file_hash = ?, ' +
             'epochs_top_layer = ?, ' +
             'top_layer_loss = ?, ' +
             'top_layer_binary_accuracy = ?, ' +
             'epochs_fine_tune_layer = ?, ' +
             'fine_tune_learning_rate = ?, ' +
             'fine_tune_loss = ?, ' +
             'fine_tune_binary_accuracy = ? ' +
             'WHERE transfer_learning_model_id = ?')

    # Arguments
    args = (transfer_learning_model_id, name, file_hash, epochs_top_layer, top_layer_loss, top_layer_binary_accuracy,
            epochs_fine_tune_layer, fine_tune_learning_rate, fine_tune_loss, fine_tune_binary_accuracy)
    # Executes the SQL query
    return self.get_result_from_query(self.sql_query(query, args))

  '''
    // End of Update Methods
  '''