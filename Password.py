# loading required libraries from mysql(accessing database), Crypto(encryption and decryption) and base64(for
# encoding and decoding of data)
import random, array
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA512
from base64 import b64encode, b64decode
import mysql.connector


# This function generates a random password every time it is called and returns it.
def password_generator():
    MAX_LEN = 14
    DIGITS = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']
    LOCASE_CHARACTERS = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
                         'i', 'j', 'k', 'm', 'n', 'o', 'p', 'q',
                         'r', 's', 't', 'u', 'v', 'w', 'x', 'y',
                         'z']
    UPCASE_CHARACTERS = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                         'I', 'J', 'K', 'M', 'N', 'O', 'p', 'Q',
                         'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y',
                         'Z']
    SYMBOLS = ['@', '#', '$', '%', '=', ':', '?', '.', '/', '|', '~', '>',
               '*', '(', ')', '<', '!']

    # contains every possible character in this list
    COMBINED_LIST = DIGITS + UPCASE_CHARACTERS + LOCASE_CHARACTERS + SYMBOLS

    # this gets a single digit every time
    rand_digit = random.choice(DIGITS)

    # this gets a single upper alphabet
    rand_upper = random.choice(UPCASE_CHARACTERS)

    # this gets a single lower alphabet
    rand_lower = random.choice(LOCASE_CHARACTERS)

    # this get a single symbol from the mentioned symbols list
    rand_symbol = random.choice(SYMBOLS)

    # this makes sure that every password has at least one Upper, Lower, Digit, Symbol
    temp_pass = rand_digit + rand_upper + rand_lower + rand_symbol
    temp_pass_list = ""

    # In this loop, we actually generate 14 length password very uniquely has it is mutated several time
    for x in range(MAX_LEN - 4):
        temp_pass = temp_pass + random.choice(COMBINED_LIST)
        temp_pass_list = array.array('u', temp_pass)
        # shuffle the list for every new character addition to temp_pass_list to make it random
        random.shuffle(temp_pass_list)
    password = ""

    # Now the password is stored in to password variable
    for x in temp_pass_list:
        password = password + x

    # return password
    return password


# This function is helpful to make a successful sql connection to the database to store and retrieve the website details
def sql_connection():
    # we store the sql user and password along with database name and host address
    db1 = mysql.connector.connect(
        host="localhost",
        user="root",
        password="root1234",
        database="security"
    )

    # create a sql cursor for altering the table
    cursor1 = db1.cursor()

    # syntax for insert statement along with the details
    sql1 = "Insert into credentials (website_name, name_nonce, name_tag, website_password, pass_nonce, pass_tag) " \
           "Values (%s, %s, %s, %s, %s, %s) "

    # pass the cursor, syntax sql statement and database variable to callee for executing the commands to store or
    # retrieve website details
    return cursor1, sql1, db1


# This function is called when ever a new entry is made and this is passed with salt value and database variables
def new_entry(salt1, cursor1, sql1, db1):

    # taking website name and master password from user
    website_name = input("Enter website name\n")
    master_password = input("Enter master password\n")

    # generate a random password
    website_password = password_generator()

    # check if the provided website name is already in the list
    status = check_entry(website_name, master_password, salt1, cursor1)

    # if it is present already, intimate user to retrieve the password
    if status == 'yes':
        print('Entered website is already in list. Try retrieving this\n')
        return

    # if website is not provided, then generate the key from pbkdf2 with salt provided
    derived_key = PBKDF2(master_password, salt1, 32, count=1000000, hmac_hash_module=SHA512)

    # generate a new cipher each for website name and password using derived key
    cipher1 = AES.new(derived_key, AES.MODE_GCM)
    cipher2 = AES.new(derived_key, AES.MODE_GCM)

    # encrypt name and password using the above generated keys
    cipher_text1 = cipher1.encrypt_and_digest(website_name.encode('utf-8'))
    cipher_text2 = cipher2.encrypt_and_digest(website_password.encode('utf-8'))

    # cipher_text* contains generated cipher_text for data, tag for validation
    cipher_text1 = list(cipher_text1)
    cipher_text2 = list(cipher_text2)

    # we are adding nonce to same list for easy data maintenance
    cipher_text1.append(cipher1.nonce)
    cipher_text2.append(cipher2.nonce)

    # we are just changing the data form to store it in database instead of gibberish
    for i in range(len(cipher_text1)):
        cipher_text1[i] = b64encode(cipher_text1[i]).decode('utf-8')
    for i in range(len(cipher_text2)):
        cipher_text2[i] = b64encode(cipher_text2[i]).decode('utf-8')

    # arrange tha data in val for insertion
    val = (cipher_text1[0], cipher_text1[2], cipher_text1[1], cipher_text2[0], cipher_text2[2], cipher_text2[1])

    # use cursor and execute the insert statement which makes a entry into database and then commit database
    # every row in database has website name and website password details
    cursor1.execute(sql1, val)
    db1.commit()


# This function checks if the entered website is already present in the list
def check_entry(w_name, m_pass, salt2, cursor2):

    # generate key to decrypt the database entries and check the real name
    derived_key = PBKDF2(m_pass, salt2, 32, count=1000000, hmac_hash_module=SHA512)
    cursor2.execute("select * from credentials")

    # all data from database is now stored in data variable( row wise)
    data = cursor2.fetchall()
    found = 'no'

    # for every row in data we will decrypt that and compare it to website name
    for line in data:
        web_name_enc = list(line)
        web_name_enc = web_name_enc[:3] # take only website name details
        for i in range(len(web_name_enc)):
            web_name_enc[i] = b64decode(web_name_enc[i]) # encode the data as we have decoded it before database entry

        # generate cipher using same nonce
        cipher = AES.new(derived_key, AES.MODE_GCM, web_name_enc[1])

        # decrypt and validate data using cipher and tag details
        web_name = cipher.decrypt_and_verify(web_name_enc[0], web_name_enc[2])
        web_name = web_name.decode('utf-8')

        # check if the extracted name is equal to entered name
        if w_name == web_name:
            found = 'yes'

    # return the status 'yes' if found.
    return found


# This function is called everytime to retrieve password
def retrieve_password(salt1, cursor1):

    # get name and master password from user
    website_name = input("Enter website name to retrieve password\n")
    master_password = input("Enter master password\n")

    # generate key from salt using pbkdf2
    derived_key = PBKDF2(master_password, salt1, 32, count=1000000, hmac_hash_module=SHA512)

    # get all the data from database
    cursor1.execute("select * from credentials")
    data = cursor1.fetchall()

    # flag to check if the requested name is in list or not
    found = 0

    # this loop see it the data extracted from database as the same name, if yes then decrypt corresponding password
    # and display it to user
    for line in data:
        web_name_enc = list(line)
        web_name_enc = web_name_enc[:3]
        for i in range(len(web_name_enc)):
            web_name_enc[i] = b64decode(web_name_enc[i])
        # print(web_name_enc)
        cipher = AES.new(derived_key, AES.MODE_GCM, web_name_enc[1])
        web_name = cipher.decrypt_and_verify(web_name_enc[0], web_name_enc[2])
        web_name = web_name.decode('utf-8')

        # if this is the website name provided then go decrypt password
        if web_name == website_name:
            web_pass_enc = list(line)
            web_pass_enc = web_pass_enc[3:]
            for i in range(len(web_pass_enc)):
                web_pass_enc[i] = b64decode(web_pass_enc[i])
            cipher1 = AES.new(derived_key, AES.MODE_GCM, web_pass_enc[1])
            web_pass = cipher1.decrypt_and_verify(web_pass_enc[0], web_pass_enc[2])
            web_pass = web_pass.decode('utf-8')
            print("Website password for ", web_name, " : ", web_pass, '\n')
            found = 1 # change the flag status to success

    # if not in list, then inform user
    if found == 0:
        print("No password is saved for this website name\n")


# This is where the main program starts
if __name__ == "__main__":

    # run the sql connection function
    cursor, sql, db = sql_connection()

    # This loop gets exited when ever the user wants to, in the mean time he can store the new details or retrieve
    # the existing details
    while True:
        option = int(input("1. For Store\n2. For Retrieve\n"))
        salt = "!yO12*^* *#nksd3"  # we have hardcoded the salt value
        # 1 for new entry
        if option == 1:
            # call the corresponding function
            new_entry(salt, cursor, sql, db)
        # 2 for retrieving
        elif option == 2:
            # call the corresponding function
            retrieve_password(salt, cursor)
        # ask for user if he wants to do more entries or he wants to exit the password manager
        option = input("Todo more entries press 'C' and other key to exit\n")
        if option == 'C':
            continue
        else:
            # close the database connections before exiting the password manager
            cursor.close()
            db.close()
            exit("\nYour passwords are saved. BYE!!!\n")


