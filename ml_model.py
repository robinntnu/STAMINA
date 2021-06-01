'''
  Author: Robin Berg Jønsson
  Created: 24.04.2021
  Last edited:
  Description: This file represents the machine learning models
  Classes:
    1.
    2.
  Methods:
    1.
    2.
    3.
    4.
'''
# Setup
import numpy as np
import tensorflow as tf
from tensorflow import keras
import cv2
import hashlib
import tensorflow_hub as hub
from tensorflow.keras.applications import InceptionV3
from tensorflow.keras.models import load_model
import datetime
import os
from pathlib import Path
from sklearn.preprocessing import LabelEncoder
from sklearn.preprocessing import OneHotEncoder
from sklearn.model_selection import train_test_split
from sklearn.model_selection import KFold
# import matplotlib.pyplot as plt
from tensorflow.keras.preprocessing import image_dataset_from_directory
import datetime
from sklearn.model_selection import StratifiedKFold

# Batch size
BATCH_SIZE = 32
# Width
IMG_WIDTH = 299
# Height
IMG_HEIGHT = 299
# Image size
IMG_SIZE = (IMG_WIDTH, IMG_HEIGHT)
# Benign or malicious images
MODEL_INPUT_TYPES = ["Benign", "Malicious"]
# RGB
COLOR_DIMENSION = 3
# Height, width, and colour channels
MODEL_INPUT_SHAPE = IMG_SIZE + (COLOR_DIMENSION,)
# Two unique labels, benign or malicious
MODEL_OUTPUT_SHAPE = len(MODEL_INPUT_TYPES)
# Sets k = 10
N_SPLIT = 5#10
# Sets the base learning rate
BASE_LEARNING_RATE = 0.01 # 0.1
# Sets the number of epochs for the top layer training
EPOCHS_TOP_LAYER = 3 # 100
# Sets the number of epochs for the fine tuning
EPOCHS_FINE_TUNING = 1


# Transfer learning model
class Transfer_Learning_Model():
    # Constructor
    def __init__(self, feature_extractor_model=True):
        # Creates a feature extractor model if True, else using fine-tuning
        self.feature_extractor_model = feature_extractor_model
        # Creates the ML model
        self.model, self.base_model = self.create_model()
        # Prints the created model
        self.summary()

    # Creates a ML model
    def create_model(self):
        # 1. Creates a feature extractor or fine-tuning model
        if self.feature_extractor_model:
            # 1.1 Creating a feature extractor model
            print('Creating a feature extractor model')
            # 1.1.1 Creating the feature extractor model based on Inception V3 and
            # replacing the last fully connected layer with a dense with the output benign or malicious.
            # The activation function is sigmoid, since this is a binary case e.g. benign or malicious
            model = tf.keras.Sequential(
                [hub.KerasLayer("https://tfhub.dev/google/tf2-preview/inception_v3/feature_vector/4",
                                output_shape=[2048],
                                trainable=False),  # Freeze the convolutional base
                 tf.keras.layers.Dense(1, activation='sigmoid')]) # MODEL_OUTPUT_SHAPE
            # 1.1.2 Builds the model
            model.build([None, IMG_WIDTH, IMG_HEIGHT, COLOR_DIMENSION])  # Batch input shape
            # Compiles the model
            model.compile(optimizer=keras.optimizers.Adam(),
                          loss=keras.losses.BinaryCrossentropy(from_logits=True),
                          metrics=[keras.metrics.BinaryAccuracy()], )
            # Return model and base_model
            return [model, None]  # model[0]?
        else:
            # 1.1 Creating a fine-tuning model
            print('Creating a fine-tuning model')
            # 1.1.1 Creating the base model (pre-trained neural network)
            base_model = InceptionV3(input_shape=MODEL_INPUT_SHAPE, weights='imagenet', include_top=False)
            # 1.1.2 Freeze the convolutional base
            #base_model.trainable = False
            index = 0
            for layer in base_model.layers:
                if index == 299:#300:  # if layer.name == 'batch_normalization_179':
                    print(f'Layers frozen until: {layer.name} Index: {index}')
                    break
                layer.trainable = False
                #print(f'Layer {index} = {layer.name} = Frozen')
                index += 1

            # 1.1.3 Creating the model layers from the pretrained model
            model = tf.keras.Sequential([base_model,
                                         tf.keras.layers.GlobalAveragePooling2D(),
                                         #tf.keras.layers.Dense(units=MODEL_OUTPUT_SHAPE, activation="sigmoid")])
                                         tf.keras.layers.Dense(1, activation="sigmoid")])
            # 1.1.4 Compiles the model
            model.compile(optimizer=keras.optimizers.Adam(BASE_LEARNING_RATE),
                          loss=keras.losses.BinaryCrossentropy(from_logits=True),
                          metrics=[keras.metrics.BinaryAccuracy()], )
            # 1.1.5 Return model and base_model
            return [model, base_model]

    # Train the model / the top layer of the model
    def train(self, train_dataset, val_dataset, test_dataset, epochs=EPOCHS_TOP_LAYER):
        print('Training')
        # Logging path
        log_directory = os.path.join(f'logs/', f'{datetime.datetime.now().strftime("%Y%m%d-%H%M%S")}')
        # Creates a TensorBoard
        model_tensorboard = tf.keras.callbacks.TensorBoard(log_directory)
        # Creates an early stop after three cycles, if they are not improving much, we stop training
        model_early_stopping = tf.keras.callbacks.EarlyStopping(monitor="binary_accuracy", patience=1) # patience=3
        # Trains the model epochs=100
        history = self.model.fit(train_dataset, epochs=epochs, callbacks=[model_tensorboard, model_early_stopping])
        # Trains the model
        #history = self.model.fit(train_dataset, epochs=epochs)  # callbacks=[model_tensorboard]
        # Evaluate the model
        evaluation = self.model.evaluate(val_dataset)
        print('Model evaluation ', evaluation)
        # Gets the predictions
        predictions = self.model.predict(test_dataset)
        print(predictions)
        # Returns the history, evaluation and predictions
        return [history, evaluation, predictions]

    #def

    # Fine-tuning the model
    def fine_tune(self, train_dataset, val_dataset, test_dataset, epochs=EPOCHS_FINE_TUNING,
                  base_learning_rate=BASE_LEARNING_RATE):
        print('Fine-tunining the model')
        # Unfreeze the base_model. Note that it keeps running in inference mode
        # since we passed `training=False` when calling it. This means that
        # the batchnorm layers will not update their batch statistics.
        # This prevents the batchnorm layers from undoing all the training
        # we've done so far.
        self.base_model.trainable = True
        # Compiling the model with given learning rate
        self.model.compile(optimizer=keras.optimizers.Adam(base_learning_rate),
                      loss=keras.losses.BinaryCrossentropy(from_logits=True),
                      metrics=[keras.metrics.BinaryAccuracy()], )
        # Training the model
        self.train(train_dataset, val_dataset, test_dataset, epochs)

    # Saving the model
    def save_model(self, model_name):
        self.model.save(f'{model_name}.h5')

    #
    # def load_model(self, path)
    # self.model

    # Gets the summary of the model
    def summary(self):
        self.model.summary()