

#IMPORTING LIBRARIES
import datetime
import hashlib
import json
from tinyec import registry
from Crypto.Cipher import AES
import secrets
import hashlib, binascii
import pandas as pd
import numpy as np
import os
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from tinyec import registry
import secrets
from Crypto.Cipher import AES
import hashlib, binascii
import seaborn as sns
import warnings
warnings.filterwarnings('ignore')
from sklearn.cluster import KMeans
from sklearn import metrics
  
#CREATING BLOCKCHAIN CLASS 
class Blockchain:

    def __init__(self):
        self.chain = []
        self.create_block(proof=1, previous_hash='0')

    def create_block(self, proof, previous_hash):
        block = {'index': len(self.chain) + 1,
                 'timestamp': str(datetime.datetime.now()),
                 'proof': proof,
                 'previous_hash': previous_hash}
        self.chain.append(block)
        return block
        
    def print_previous_block(self):
        return self.chain[-1]
        
    def proof_of_work(self, previous_proof):
        new_proof = 1
        check_proof = False
          
        while check_proof is False:
            hash_operation = hashlib.sha256(
                str(new_proof**2 - previous_proof**2).encode()).hexdigest()
            if hash_operation[:4] == '0000':
                check_proof = True
            else:
                new_proof += 1
                  
        return new_proof
  
    def hash(self, block):
        encoded_block = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(encoded_block).hexdigest()
  
    def chain_valid(self, chain):
        previous_block = chain[0]
        block_index = 1
          
        while block_index < len(chain):
            block = chain[block_index]
            if block['previous_hash'] != self.hash(previous_block):
                return False
                
            previous_proof = previous_block['proof']
            proof = block['proof']
            hash_operation = hashlib.sha256(
                str(proof**2 - previous_proof**2).encode()).hexdigest()
              
            if hash_operation[:4] != '0000':
                return False
            previous_block = block
            block_index += 1
          
        return True

#ECC ENCRYTION AND DECRYPTION WITH AES
def encryption_AES(msg, secretKey):
    aesCipher = AES.new(secretKey, AES.MODE_GCM)
    ciphertext, authTag = aesCipher.encrypt_and_digest(msg)
    return (ciphertext, aesCipher.nonce, authTag)

def decryption_AES(ciphertext, nonce, authTag, secretKey):
    aesCipher = AES.new(secretKey, AES.MODE_GCM, nonce)
    plaintext = aesCipher.decrypt_and_verify(ciphertext, authTag)
    return plaintext

def ecc_to_256_bitkey(point):
    sha = hashlib.sha256(int.to_bytes(point.x, 32, 'big'))
    sha.update(int.to_bytes(point.y, 32, 'big'))
    return sha.digest()

curve = registry.get_curve('brainpoolP256r1')


def ECC_Encrytion(msg, pubKey):
    ciphertextPrivKey = secrets.randbelow(curve.field.n)
    sharedECCKey = ciphertextPrivKey * pubKey
    secretKey = ecc_to_256_bitkey(sharedECCKey)
    ciphertext, nonce, authTag = encryption_AES(msg, secretKey)
    ciphertextPubKey = ciphertextPrivKey * curve.g
    return (ciphertext, nonce, authTag, ciphertextPubKey)

def ECC_Decrytion(storedMsg, privKey):
    (ciphertext, nonce, authTag, ciphertextPubKey) = storedMsg
    sharedECCKey = privKey * ciphertextPubKey
    secretKey = ecc_to_256_bitkey(sharedECCKey)
    plaintext = decryption_AES(ciphertext, nonce, authTag, secretKey)
    return plaintext

#-------------------------------------------------------------------------------------------------
blockchain = Blockchain()
previous_block = blockchain.print_previous_block()
previous_proof = previous_block['proof']
proof = blockchain.proof_of_work(previous_proof)
previous_hash = blockchain.hash(previous_block)
block = blockchain.create_block(proof, previous_hash)

#lOADING DATASET
df=pd.read_csv('creditcard.csv')
df=df.iloc[:10]


lak = df.to_numpy().flatten()

encrypt = []
decrypt = []
for j in lak:
    j = str(j)
    msg = str.encode(j)    
    privKey = secrets.randbelow(curve.field.n)
    pubKey = privKey * curve.g
    
    encryptedMsg = ECC_Encrytion(msg, pubKey)
    encrypt.append(encryptedMsg)
      
    response = {'message': encryptedMsg,
                'index': block['index'],
                'timestamp': block['timestamp'],
                'proof': block['proof'],
                'previous_hash': block['previous_hash']} 
    response2 = {'chain': blockchain.chain,
                    'length': len(blockchain.chain)} 
    valid = blockchain.chain_valid(blockchain.chain)
          
    if valid:
        print( ' Block is valid.')
        storedMsg=response["message"]
        #print(storedMsg)
        decryptedMsg = ECC_Decrytion(storedMsg, privKey)
        decryptedMsg = decryptedMsg.decode('utf-8')
        decrypt.append(decryptedMsg)
        
        print("decrypted msg:", decryptedMsg)
    else:
        print( ' block is not valid.')
    
"Blockchain Encryption and decryption "

def AES_Encryption(msg, secretKey):
    aesCipher = AES.new(secretKey, AES.MODE_GCM)
    ciphertext, authTag = aesCipher.encrypt_and_digest(msg)
    return (ciphertext, aesCipher.nonce, authTag)

def AES_Decryption(ciphertext, nonce, authTag, secretKey):
    aesCipher = AES.new(secretKey, AES.MODE_GCM, nonce)
    plaintext = aesCipher.decrypt_and_verify(ciphertext, authTag)
    return plaintext

def ECC_bit_key_generation(point):
    sha = hashlib.sha256(int.to_bytes(point.x, 32, 'big'))
    sha.update(int.to_bytes(point.y, 32, 'big'))
    return sha.digest()

curve = registry.get_curve('brainpoolP256r1')

def ECC_Encryption(msg, pubKey):
    ciphertextPrivKey = secrets.randbelow(curve.field.n)
    sharedECCKey = ciphertextPrivKey * pubKey
    secretKey = ECC_bit_key_generation(sharedECCKey)
    ciphertext, nonce, authTag = AES_Encryption(msg, secretKey)
    ciphertextPubKey = ciphertextPrivKey * curve.g
    return (ciphertext, nonce, authTag, ciphertextPubKey)

def ECC_Decryption(encryptedMsg, privKey):
    (ciphertext, nonce, authTag, ciphertextPubKey) = encryptedMsg
    sharedECCKey = privKey * ciphertextPubKey
    secretKey = ECC_bit_key_generation(sharedECCKey)
    plaintext = AES_Decryption(ciphertext, nonce, authTag, secretKey)
    return plaintext

#----------------------------------------------------------------------------------------


df1 = pd.read_csv("creditcard.csv") 
df1=df1.iloc[:10]
df1.shape

column_names = list(df.columns)

result = df.values

print("Encrypting and Decrypting the CSV file...")  
empty = []
empty_decoded = []
for i in result:
    for j in i:
        a = str(j)
        en = a.encode()
        s = ECC_Encrytion(en, pubKey)
        b = binascii.hexlify(s[0])
        encoded_text = b.decode('utf-8')
        empty.append(encoded_text)
        #print(f"Encoded Text : {encoded_text}")
        
        
        de = ECC_Decryption(s, privKey)
        decoded_text = de.decode('utf-8')
        empty_decoded.append(decoded_text)
        #print(f"Decoded Text  : {decoded_text}")
     
encrypted_df = pd.DataFrame(np.array(empty).reshape(10,31),columns = column_names)

print("Encryption Completed and written as encryption.csv file")
encrypted_df.to_csv(r'encrypted.csv',index = False)

print("decryption Completed and written as Decryption.csv file")

decrypted_df = pd.DataFrame(np.array(decrypt).reshape(10,31),columns =df.columns)
decrypted_df.to_csv(r'decryption.csv',index = False)

decrypted_df.head()  



#---------------------------------------------------------------------------
"Load a dataset"
print("DATASET LOADED SUCESSFULLY....")
df=decrypted_df

#----------------------------------------------------------------------------

print("CHECKING ANY VALUE ARE MISSING IN DATASET")
df.isnull().sum()

#--------------------------------------------------------------------------
len(df)
nRow, nCol = df.shape
print(f'There are {nRow} rows and {nCol} columns')
#-----------------------------------------------------------------------

print(f"Duplicated rows: {df.duplicated().sum()}")

#---------------------------------------------------------------------------





"Import Libaries "

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
from sklearn import metrics


import tensorflow as tf
import numpy as np
import matplotlib.pyplot as plt
from tensorflow.keras.layers import Conv1D, Flatten, BatchNormalization, LeakyReLU, Input, Dropout, Dense, Add, Dropout
from tensorflow.keras import Model, datasets, models
from tensorflow.keras.optimizers import Adam

import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

data = pd.read_csv('creditcard.csv')

data.tail()

data.shape

data.isnull().sum()

data.info()

data['Class'].value_counts()

# This is Highly inbalance data as for non-fraud=284315 and for fraud=492 so we need to balance it

non_ponzi = data[data['Class']==0]
ponzi = data[data['Class']==1]

non_ponzi.shape, ponzi.shape


non_ponzi = non_ponzi.sample(ponzi.shape[0])

# Now it is balanced dataset
non_ponzi.shape, ponzi.shape

# Merging fraud and non_fraud data
new_data = ponzi.append(non_ponzi, ignore_index=True)

new_data['Class'].value_counts()

new_data

# saperating features and predicting value
# x contains our all featurs
# y contains output which needs to be predicted

x = new_data.drop('Class', axis=1)
y = new_data['Class']

# spliting data

x_train, x_test, y_train, y_test = train_test_split(x, y, test_size=0.25, stratify=y)

# Feature scaling with mean normalization for x data
# for x_test only transform is used to avoid overfitting

scaler = StandardScaler()
x_train = scaler.fit_transform(x_train)
x_test = scaler.fit_transform(x_test)

# converting y data into numpy

y_train = np.array(y_train)
y_test = np.array(y_test)

# reshape data as keras model takes 3-D data i.e. expanding 1 dimension

x_train = x_train.reshape(x_train.shape[0], x_train.shape[1], 1)
x_test = x_test.reshape(x_test.shape[0], x_test.shape[1], 1)

# CNN MODEL

# Convolutional Neural Network

init = tf.random_normal_initializer(0.,0.2)

def fraud():
    I = Input(shape=x_train[0].shape)
    
    C1 = Conv1D(32, 2, kernel_initializer=init)(I)
    B1 = BatchNormalization()(C1)
    L1 = LeakyReLU()(C1)
    D1 = Dropout(0.5)(L1)
    
    C2 = Conv1D(64, 2, kernel_initializer=init)(L1)
    B2 = BatchNormalization()(C2)
    L2 = LeakyReLU()(B2)
    D2 = Dropout(0.5)(L2)
    
    F3 = Flatten()(D2)   
    DE3 = Dense(64)(F3)
    L3 = LeakyReLU()(DE3)
    D3 = Dropout(0.5)(L3)

    
    out = Dense(1, activation='sigmoid')(D3)
    
    model = Model(inputs=I, outputs=out)
    
    return model
    

model = fraud()
model.summary()

model.compile(optimizer=Adam(lr=0.0001), loss='binary_crossentropy', metrics=['accuracy'])

train = model.fit(x_train, y_train, validation_split=0.1, batch_size=10, epochs=50)
y_pred=model.predict(x_test)
y_pred=y_pred.round()

# Plots to display loss and accuracy

plt.figure()
plt.plot(train.history['accuracy'])
plt.plot(train.history['val_accuracy'])
plt.title('model accuracy')
plt.ylabel('accuracy')
plt.xlabel('epoch')
plt.legend(['train', 'test'], loc='upper left')
plt.show()

plt.figure()
plt.plot(train.history['loss'])
plt.plot(train.history['val_loss'])
plt.title('model loss')
plt.ylabel('loss')
plt.xlabel('epoch')
plt.legend(['train', 'test'], loc='upper left')
plt.show()

pred = model.predict(x_test)

# Prediction
np.round(pred.astype('int32'))


#---------------------------------------------------------------------------------------------

from easygui import *
Key = "Enter the  Id to be Search"  
# window title
title = "Credit card Spam "
# creating a integer box
str_to_search1 = enterbox(Key, title)
input = int(str_to_search1)

import tkinter as tk
if (y_pred[input] ==0 ):
    print("Non ponzi ")
    root = tk.Tk()
    T = tk.Text(root, height=20, width=30)
    T.pack()
    T.insert(tk.END, "Non ponzi ")
    tk.mainloop()
elif (y_pred[input] ==1 ):
    print("ponzi ")
    root = tk.Tk()
    T = tk.Text(root, height=20, width=30)
    T.pack()
    T.insert(tk.END, "ponzi ")
    tk.mainloop()
    import smtplib as smtp
    
    connection = smtp.SMTP_SSL('smtp.gmail.com', 465)
        
    email_addr = 'sathyakumar17112022@gmail.com'
    email_passwd = 'ncfplwzacztjnxyp'
    connection.login(email_addr, email_passwd)
    connection.sendmail(from_addr=email_addr, to_addrs='arjunkingarjun432@gmail.com', msg="Attack kindly prevent DOs")
    connection.close()

