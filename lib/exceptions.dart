///An exception thrown when the algorithm entered by user is not supported
class UnsupportedAlgorithmException implements Exception {
  ///The description for the exception.
  String cause;

  ///Exception constructor containing the description for the exception.
  UnsupportedAlgorithmException(this.cause);
  @override
  String toString() => "UnsupportedAlgorithmException: $cause";
}

///An exception thrown when the algorithm has not been initialized
class AlgorithmNotSetException implements Exception{
  ///The description for the exception.
  String cause;

  ///Exception constructor containing the description for the exception.
  AlgorithmNotSetException(this.cause);
  @override
  String toString() => "AlgorithmNotSetException: $cause";
}

class NoKeyInStorageException implements Exception {
  ///The description for the exception.
  String cause;

  ///Exception constructor containing the description for the exception.
  NoKeyInStorageException(this.cause);
  @override
  String toString() => "NoKeyInStorageException: $cause";
}

///An exception thrown when there is no secure screen lock set on the device.
class DeviceNotSecuredException implements Exception {
  ///The description for the exception.
  String cause;

  ///Exception constructor containing the description for the exception.
  DeviceNotSecuredException(this.cause);
  @override
  String toString() => "DeviceNotSecuredException: $cause";
}

///An exception thrown when the data signature is invalid.
class InvalidSignatureException implements Exception {
  ///The description for the exception.
  String cause;

  ///Exception constructor containing the description for the exception.
  InvalidSignatureException(this.cause);
  @override
  String toString() => "InvalidSignatureException: $cause";
}

///An exception thrown when there is an error in shared preferences.
class SharedPreferencesException implements Exception {
  ///The description for the exception.
  String cause;

  ///Exception constructor containing the description for the exception.
  SharedPreferencesException(this.cause);
  @override
  String toString() => "SharedPreferencesException: $cause";
}