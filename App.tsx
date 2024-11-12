


import React, { useState } from 'react';
import { View, Text, Button, Alert, StyleSheet, ScrollView } from 'react-native';


import DeviceCrypto from 'react-native-device-crypto';
const { getOrCreateSymmetricKey, encrypt, decrypt, authenticateWithBiometry } = DeviceCrypto;

import { NativeModules } from 'react-native';
const { GetTrueRandomNumber } = NativeModules;

export default function App() {

  const [trueRandomNumber, setTrueRandomNumber] = useState<string>('');
  const [encryptedData, setEncryptedData] = useState([]);
  const [retrivedTRN, setRetrivedTRN] = useState([]);

  const alias = 'secureKeyAlias'; // The key alias



  //Method 1: Get True Random Number
  const getTrueRandomNumberFunction =  async () => {

    try {
      let generatedTrueNumber = await GetTrueRandomNumber.getTrueRandomNumber();
      console.log('Generated Random True String:', generatedTrueNumber);
      setTrueRandomNumber(generatedTrueNumber);

    }catch (error) {
      console.error("Error in Generating True Random Number", error);
      Alert.alert('Error', 'Something went wrong during generating true random string.');
    }
  }

 //Method 2: Split TRN and Encrypt it
 const splitTRNAndEncryptFunction = async () => {
  try {
    // PART 1: Splitting TRN
    let isValid = false;
    let splitSharesArray: string[] = [];

    // Loop until we get a valid splitSharesArray (not equal to ["1-", "2-", "3-", "4-", "5-"])
    while (!isValid) {
      splitSharesArray = await GetTrueRandomNumber.splitSecret(trueRandomNumber);
      console.log('Split Shares Array:', splitSharesArray);

      isValid = !splitSharesArray.every((part, index) => part === `${index + 1}-`);
    }

    // PART 2: Encrypting the splitted shares using hardware (Secure Enclave)
    let encryptedArray: (string | null)[] = [];
    let isEncryptionValid = false;

    // Retry loop for encryption
    while (!isEncryptionValid) {
      // 1. Create a symmetric key in secure hardware
      const options = { accessLevel: "AUTHENTICATION_REQUIRED" };
      const isKeyCreated = await DeviceCrypto.getOrCreateSymmetricKey(alias, options);

      if (!isKeyCreated) {
        Alert.alert('Error', 'Failed to create or access the symmetric key');
        return;
      }

      // 2. Perform biometric authentication
      const isAuthenticated = await DeviceCrypto.authenticateWithBiometry({
        reason: 'Please authenticate to encrypt data',
      });

      if (!isAuthenticated) {
        Alert.alert('Authentication Failed', 'Biometric authentication failed');
        return;
      }

      // 3. Encrypt the shares
      encryptedArray = []; // Reset the array for each retry
      for (const str of splitSharesArray) {
        const encryptionResult = await DeviceCrypto.encrypt(alias, str, { reason: 'Encrypting data' });

        if (encryptionResult?.encryptedText) {
          encryptedArray.push(encryptionResult.encryptedText);
        } else {
          console.warn('Encryption failed for:', str);
          encryptedArray.push(null);
        }
      }

      console.log("Encrypted Array is: ", encryptedArray);

      // Check if encryption was successful for all items
      isEncryptionValid = encryptedArray.length > 0 && encryptedArray.every((item) => item !== null);

      if (!isEncryptionValid) {
        console.warn('Retrying encryption as the encrypted array is invalid or empty.');
      }
    }

    setEncryptedData(encryptedArray);

  } catch (error) {
    console.error("Error in Splitting and Encrypting TRN", error);
    Alert.alert('Error', 'Something went wrong during Splitting and Encrypting TRN');
  }
};



  //Method 3: Decrypt the shares and get back TRN

  const decryptDataAndGetBackTRNFunction = async () => {
    try {

      //Part 1: Decrypt

       // 1. Perform biometric authentication (Face ID or fingerprint)
      const isAuthenticated = await authenticateWithBiometry({
        reason: 'Please authenticate to decrypt data'
      });

      if (isAuthenticated) {
        let decryptedArray = [];

        // 2. Decrypt each string in the encrypted array
        for (const encryptedStr of encryptedData) {
          //const decryptedString = await decrypt(alias, encryptedStr, '', { reason: 'Decrypting data' });
          //decryptedArray.push(decryptedString);

          const decryptedString = await decrypt(alias, encryptedStr, '', { reason: 'Decrypting data' });
          if (decryptedString === null) {
            console.warn('Decryption failed for:', encryptedStr);
            decryptedArray.push('Decryption failed');
          } else {
            decryptedArray.push(decryptedString);
          }
        }

        //PART 2: Recontruct TRN
        const retrievedNumber = await GetTrueRandomNumber.retriveTrueRandomNumber(decryptedArray);
        console.log('Retrieved True Random Number:', retrievedNumber);
        setRetrivedTRN(retrievedNumber)

      } else {
        Alert.alert('Authentication Failed', 'Biometric authentication failed');
      }
    } catch (error) {
      console.error(error);
      Alert.alert('Error', 'Something went wrong during decryption and getting back TRN');
    }
  };

  return (
    <ScrollView>
      <View style={styles.container}>
        
        <Text style={styles.title}>React Native Secure Encryption</Text>

        <Button title="Get True Random Number" onPress={getTrueRandomNumberFunction} />
        <Text>{trueRandomNumber}</Text>
        <Button title="Split & Encrypt TRN" onPress={splitTRNAndEncryptFunction} />
        <Text>{JSON.stringify(encryptedData, null, 2)}</Text>
        <Button title="Decrypt & Get Back TRN" onPress={decryptDataAndGetBackTRNFunction} />
        <Text>{retrivedTRN}</Text>

      </View>
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
    padding: 20
  },
  title: {
    fontSize: 20,
    fontWeight: 'bold',
    marginBottom: 20
  },
  sectionTitle: {
    fontSize: 18,
    fontWeight: '600',
    marginTop: 20
  }
});

/*
import React, { useState } from 'react';
import { View, Text, Button, Alert, StyleSheet, ScrollView } from 'react-native';


import DeviceCrypto from 'react-native-device-crypto';
const { getOrCreateSymmetricKey, encrypt, decrypt, authenticateWithBiometry } = DeviceCrypto;

import { NativeModules } from 'react-native';
const { GetTrueRandomNumber } = NativeModules;

export default function App() {

  const [trueRandomNumber, setTrueRandomNumber] = useState<string>('');
  const [splitedSharesArray, setSplitedSharesArray] = useState<string[]>([]);
  const [encryptedData, setEncryptedData] = useState([]);

  const [decryptedData, setDecryptedData] = useState([]);

  const alias = 'secureKeyAlias'; // The key alias
  let stringsToEncrypt = [
    "Hello, world!",
    "Secure this data.",
    "React Native encryption.",
    "Biometric authentication.",
    "Face ID example."
  ];


  const getTrueRandomNumberAndGetSplittedArray = async () => {
    console.log("Hello Test")
    try {
      let isValid = false;
      let generatedTrueNumber: string | null = null;
      let splitSharesArray: string[] = [];
  
      // Loop until we get a valid splitSharesArray (not equal to ["1-", "2-", "3-", "4-", "5-"])
      while (!isValid) {
        // Generate True Random Number
        generatedTrueNumber = await GetTrueRandomNumber.getTrueRandomNumber();
        console.log('Generated Random True String:', generatedTrueNumber);
        setTrueRandomNumber(generatedTrueNumber);
  
        // Split Secret into parts
        splitSharesArray = await GetTrueRandomNumber.splitSecret(generatedTrueNumber);
        console.log('Split Shares Array:', splitSharesArray);
  
        // Check if the splitSharesArray is valid
        isValid = !splitSharesArray.every((part, index) => part === `${index + 1}-`);
  
        // Optional: Break if attempts exceed a certain count to prevent infinite loop
        // if (attempts > 5) break;
      }
  
      setSplitedSharesArray(splitSharesArray);
  
    } catch (error) {
      console.error("Error in getTrueRandomNumberAndGetSplittedArray:", error);
      Alert.alert('Error', 'Something went wrong during generating random string.');
    }
  };

  

  //old code commented
  /*
  const getTrueRandomNumberAndGetSplitedArray = async () => {

    try {
      //Generate True Random Number
      const generatedTruNumber = await GetTrueRandomNumber.getTrueRandomNumber();
      console.log('Generated Random True String:', generatedTruNumber);
      setTrueRandomNumber(generatedTruNumber); // Store the generated number in state

     //Split Secret into 5 parts
     const getSplitedSharesArray: string[] = await GetTrueRandomNumber.splitSecret(trueRandomNumber);
     console.log('Splited Shares Array:', getSplitedSharesArray);
     setSplitedSharesArray(getSplitedSharesArray)
     //Splited Shares Array: ["1-", "2-", "3-", "4-", "5-"]

    } catch (error) {
      console.error(error);
      Alert.alert('Error', 'Something went wrong during generating random string.');
    }
  }
  */
  //old code commented


  //
  /*
  // Encrypt the array of strings
  const encryptData = async () => {

    try {

      // 1. Create a symmetric key in secure hardware
      const options = { accessLevel: "AUTHENTICATION_REQUIRED" };  // Using string literal
      const isKeyCreated = await DeviceCrypto.getOrCreateSymmetricKey(alias, options);

      if (!isKeyCreated) {
        Alert.alert('Error', 'Failed to create or access the symmetric key');
        return;
      }
      
      //const isBiometryEnrolled = await DeviceCrypto.isBiometryEnrolled();
      //if (!isBiometryEnrolled) {
       // Alert.alert('Biometric Not Set Up', 'Please set up biometrics on your device');
        //return;
      //}
      
      // 2. Perform biometric authentication
      const isAuthenticated = await DeviceCrypto.authenticateWithBiometry({
        reason: 'Please authenticate to encrypt data',
      });

      if (!isAuthenticated) {
        Alert.alert('Authentication Failed', 'Biometric authentication failed');
        return;
      }

      let encryptedArray = []; 
      for (const str of splitedSharesArray) { //stringsToEncrypt //splitedSharesArray
        const encryptionResult = await DeviceCrypto.encrypt(alias, str, { reason: 'Encrypting data' });
        //console.log("encryptionResult: ", encryptionResult);

        // Check if the encryption was successful based on `encryptedText`
        if (encryptionResult?.encryptedText) {
          encryptedArray.push(encryptionResult.encryptedText);
        } else {
          console.warn('Encryption failed for:', str);
          encryptedArray.push(null);  // Log a warning if encryption fails
        }
      }
      console.log("Encrypted Array is: ",encryptedArray);

      setEncryptedData(encryptedArray);
      Alert.alert('Encryption Success', 'Data encrypted successfully');
    } catch (error) {
      console.error(error);
      Alert.alert('Error', 'Something went wrong during encryption');
    }
  
  };


  // Decrypt the array of encrypted strings
  const decryptData = async () => {
    try {
      // 1. Perform biometric authentication (Face ID or fingerprint)
      const isAuthenticated = await authenticateWithBiometry({
        reason: 'Please authenticate to decrypt data'
      });

      if (isAuthenticated) {
        let decryptedArray = [];

        //let testEncryptedArr = ["BLABmTZNAw+PHOpWA9iWyWoWxHjZCK65G2VQsEdgSaZ+yMl5Sz0bqICxreg4jxahDsSAupPmi4rnPsPN95py8ehD9YzYhOI7XxAzBnNBXbsaq55JF0gWM3FXzhGJog==", "BNyhs7RUcha2q87Jkgc7aP74fXI2IGaRf0pxzxhKAjQ0nHwly9vHfB9PoOlvBsAeZTMwPo/U/osfMZrpyTanzA2p3IE8pHHOY293TalGWroG9BXOUlqHRgw/s5t383xoz3s=", "BHcoN6M8zyc9zGIoLBy62gzafE2ex+ASA3prZGoVgwfJ8pozBNyFTDm0pdnbflDXiLk0MX2SCv+dz34i5sOEAYMgHqSA93L25EcQG2HNqXy9TAXL+JZohw/nSokgt2SGtATIBYEklbrP", "BFvyvIDEYizAtzxrDp/P2RH9InXbL+pPD4Bs+zIyTFE+Lu8qtRuUJRZRhR1kdcEMS094rShV/6ebWZCu87MPfmaqh5PRisldV66Br/aBjrYNoa9e5frXzX2PsuN0aBokPl3NUa5U1rsleA==", "BCh3doEWXwlWSL8B2+BYtZT7bQcV/W6sT7Wa8P10HSBZHKXrWhGDxt74oUKsbOzLk59BIPuJ1bZJF4qYdT8YRZio9UUGstcYdPLyxYNGWHd9+tImYSfsZPGfAnTKa3qyow=="];
        //let encryptedData = ["BAy/vb2ut7oScYnAI7auKGZvRbmRnnqRy9J5ndwlA1pDduUL44et7AZQPxtTWipfCwlfwdS1e8xbcPBX8JyD8pePeBWKYjqtDzC/hdEV4gq/y+QXBMJVq+7F1klABjCaaZ0nf5cw09mTQQ6aTi8Bsnbs25GCLtfvEkQ0z9k1Ge6RTbGaldh0RpMreGk9YlpzsS8/TTPswm/z+qV7vj+wiVpb3YNZarRZtHA27SSlqBSykc8=", "BC0T2YI0I0jPRegXVIOVvAeJOusEKvZXOBOs39RaLkToBfQV2KbHMenYFwUG9p8NvOKcC21ippZ08DVZHntsWIa5auw3vAcoPnAXdtO3wTMmDDnn8GfbfZaH5z1C0cUeyCls7qDc0mG95coycP4A3jBBdWgwX8pwZMI0ZcgvEYQqJ/hBufa5++1WprkpP6hVMae3fZQqXujyG2AX/Ltr9cx0HZjvfXWHJsL0Qav1icDNKSw=", "BC+lPYpEXmQndX064uko9w1pb4flk5fD95RSJ85c0iaX49oM2lTMOFpjuI60OZmFhXNglpHndwdROmJ6Q3+rAPOWQhJiZ57TyBAyBXCFb4WOjenf+GfXDwjr0j4R589yZd63joqK8wBtiOmUJwQVp+kd2iKRRgNnyHK1oqjW12Edp8JXizD7WL/KAV7srdwC+B61B31iSWOfYwxgW3Q1S4O9qOiY/XHd+ty6kXGqNN96gA8=", "BN1IOn3qP4Btx8lbmSty6imxQlXH9PsLFMYksscHZvoACkdsX8UeXHkCUbL4safnuK+sNd9uIHU5yu852VcdrB9ZTjhvWZfMSu1tfSuGy0URrd7AEqHoJvt9nVlENV+qx0YqspyLX/UP5Rtya0Iynwu1bqm8H+jWBR/IT4WMlbr1swHul6UtYnp9H5pymaVsOER5Gj6zNk7KSVcmHQKVCUBoqGfLpQ3dmjjIQLuD5StTZ/o=", "BKBkrjbIqXFBEIegPIZIuVgtoT89CGLz3opWtx6JeQuN+BcFRZUuDVsd8MwNvXWwnZ/ffBfKlI1WsBYkL4jzQajiwjBY/5nKx9SPSDsFM9FTUyUVqgpMbhkLkuJiYyWZxx9Va18rJw39tLo67crw8LVzFMlt/oe0ng9MgZ/fwbRbXZHGEQ+h1YBVYTU3tDv87XooSFwMMpVwyNsjd/SWt7b0Voskcz6y4vYl3c3a4dc9YIU="]

        // 2. Decrypt each string in the encrypted array
        for (const encryptedStr of encryptedData) {
          //const decryptedString = await decrypt(alias, encryptedStr, '', { reason: 'Decrypting data' });
          //decryptedArray.push(decryptedString);

          const decryptedString = await decrypt(alias, encryptedStr, '', { reason: 'Decrypting data' });
          if (decryptedString === null) {
            console.warn('Decryption failed for:', encryptedStr);
            decryptedArray.push('Decryption failed');
          } else {
            decryptedArray.push(decryptedString);
          }
        }

        // Store the decrypted array
        setDecryptedData(decryptedArray);
        Alert.alert('Decryption Success', 'Data decrypted successfully');
      } else {
        Alert.alert('Authentication Failed', 'Biometric authentication failed');
      }
    } catch (error) {
      console.error(error);
      Alert.alert('Error', 'Something went wrong during decryption');
    }
  };

  const retriveTrueRandomNumber = async () => {

    const retrievedNumber = await GetTrueRandomNumber.retriveTrueRandomNumber(decryptedData);
    console.log('Retrieved True Random Number:', retrievedNumber);

  };

  return (
    <ScrollView>
      <View style={styles.container}>
        <Text style={styles.title}>React Native Secure Encryption</Text>

        <Button title="Get True Random Number & Get Splited Shares Array" onPress={getTrueRandomNumberAndGetSplittedArray} />
        <Button title="Encrypt Received Shares" onPress={encryptData} />

        <Button title="Decrypt Received Shares" onPress={decryptData} />

        <Button title="Get Back True Random Number" onPress={retriveTrueRandomNumber} />

        <Text style={styles.sectionTitle}>Encrypted Data:</Text>
        <Text>{JSON.stringify(encryptedData, null, 2)}</Text>

        <Text style={styles.sectionTitle}>Decrypted Data:</Text>
        <Text>{JSON.stringify(decryptedData, null, 2)}</Text>
      </View>
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
    padding: 20
  },
  title: {
    fontSize: 20,
    fontWeight: 'bold',
    marginBottom: 20
  },
  sectionTitle: {
    fontSize: 18,
    fontWeight: '600',
    marginTop: 20
  }
});

*/

//On Android, give permissions for biometrics in AndroidManifest.xml
//<uses-permission android:name="android.permission.USE_BIOMETRIC"/>

//On iOS, add the following keys to your Info.plist
//<key>NSFaceIDUsageDescription</key>
//<string>This app requires Face ID to encrypt and decrypt your data</string>
