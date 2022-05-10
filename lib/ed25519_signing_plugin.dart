
import 'dart:async';

import 'package:flutter/services.dart';

import 'exceptions.dart';

class Ed25519SigningPlugin {
  static const MethodChannel _channel = MethodChannel('ed25519_signing_plugin');

  ///Writes provided data under provided key in shared preferences. Data is signed and encrypted using AES.
  ///Works only if the device has a secure screen lock set, otherwise throws an exception. Returns true if data is successfully saved.
  static Future<bool> writeData(String key, String data) async {
    bool isDeviceSecure = await _channel.invokeMethod("checkIfDeviceSecure");
    if (isDeviceSecure) {
      var algorithm = await _channel.invokeMethod("getAlgorithm");
      var signedData = await _channel.invokeMethod("sign$algorithm", {'message' : data});
      var result = await _channel
          .invokeMethod('writeData', {'key': key, 'data': signedData});
      if (result == true) {
        return true;
      } else {
        throw SharedPreferencesException(
            'Writing to shared preferences failed. Consider reopening or reinstalling the app.');
      }
    }
    throw DeviceNotSecuredException(
        'Secure lock on this device is not set up. Consider setting a pin or pattern.');
  }

  ///Reads data saved under provided key from shared preferences. First, data signature is verified and if it is valid, data are decrypted.
  ///Works only if the device has a secure screen lock set, otherwise throws an exception. Returns data if it is successfully read.
  static Future<dynamic> readData(String key) async {
    bool isDeviceSecure = await _channel.invokeMethod("checkIfDeviceSecure");
    if (isDeviceSecure) {
      var data = await _channel.invokeMethod('readData', {'key': key});
      if (data != false) {
        var algorithm = await _channel.invokeMethod("getAlgorithm");
        bool isValid = await _channel.invokeMethod("verify$algorithm", {'message' : data});
        if (isValid) {
          return data.toString().substring(
              data.toString().indexOf(':') + 1, data.toString().length);
        }
        throw InvalidSignatureException('Data signature is not valid.');
      } else {
        throw NoKeyInStorageException(
            'No such key found in phone storage. Consider saving it to storage before reading.');
      }
    }
    throw DeviceNotSecuredException(
        'Secure lock on this device is not set up. Consider setting a pin or pattern.');
  }

  ///Deletes data saved under provided key from shared preferences.
  ///Works only if the device has a secure screen lock set, otherwise throws an exception. Returns true if data is successfully deleted.
  static Future<bool> deleteData(String key) async {
    bool isDeviceSecure = await _channel.invokeMethod("checkIfDeviceSecure");
    if (isDeviceSecure) {
      var result = await _channel.invokeMethod('deleteData', {'key': key});
      if (result != false) {
        return true;
      } else {
        throw SharedPreferencesException(
            'Writing to shared preferences failed. Consider reopening or reinstalling the app.');
      }
    }
    throw DeviceNotSecuredException(
        'Secure lock on this device is not set up. Consider setting a pin or pattern.');
  }

  ///Edits data under provided key in shared preferences. Data is signed and encrypted using AES.
  ///Works only if the device has a secure screen lock set, otherwise throws an exception. Returns true if data is successfully saved.
  static Future<bool> editData(String key, String data) async {
    bool isDeviceSecure = await _channel.invokeMethod("checkIfDeviceSecure");
    if (isDeviceSecure) {
      var algorithm = await _channel.invokeMethod("getAlgorithm");
      String signedData = await _channel.invokeMethod("sign$algorithm", {'message' : data});
      var result = await _channel
          .invokeMethod('editData', {'key': key, 'data': signedData});
      if (result == true) {
        return true;
      } else {
        throw SharedPreferencesException(
            'Writing to shared preferences failed. Consider reopening or reinstalling the app.');
      }
    }
    throw DeviceNotSecuredException(
        'Secure lock on this device is not set up. Consider setting a pin or pattern.');
  }

  ///Sets the algorithm the user will be using while signing or verifying data.
  ///Accepts string and currently supports Ed25519 and RSA, any other string will throw an exception.
  static Future<void> setAlgorithm(String algorithm) async{
    bool isDeviceSecure = await _channel.invokeMethod("checkIfDeviceSecure");
    if(isDeviceSecure){
      if(algorithm == "Ed25519" || algorithm == "RSA"){
        await _channel.invokeMethod("setAlgorithm");
      }else{
        throw UnsupportedAlgorithmException('This algorithm is not supported. Currently supported algorithms: RSA, Ed25519');
      }
    }else{
      throw DeviceNotSecuredException(
          'Secure lock on this device is not set up. Consider setting a pin or pattern.');
    }
  }

  ///Signs the provided string using chosen algorithm.
  ///In order to work correctly, a secure screen lock has to be set up (this can be checked with checkIfDeviceSecure()).
  ///Returns signed data as "signature:data" if signing succeeds or false. An asynchronous function, has to be awaited.
  static Future<dynamic> signData(String data) async {
    var algorithm = await _channel.invokeMethod("getAlgorithm");
    var result = await _channel.invokeMethod('sign$algorithm', {'data': data});
    if (result != false) {
      return result;
    } else {
      return false;
    }
  }

  ///Verifies provided data with local certificate. Returns true if the signature is valid and false if it's not.
  ///An asynchronous function, has to be awaited.
  static Future<bool> verifyData(String data) async {
    var result = await _channel.invokeMethod('verifyData', {'data': data});
    if (result == true) {
      return true;
    } else {
      return false;
    }
  }


}
