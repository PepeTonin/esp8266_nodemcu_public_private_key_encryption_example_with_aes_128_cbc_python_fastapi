const String DEVICE_ID = "XXXX";


/*BEGIN CRYPT CONFIGS**************************************************************/
const char RSA_PRIVATE_KEY[] = R"KEY(
-----BEGIN PRIVATE KEY-----
ADD YOUR PRIVATE KEY HERE
-----END PRIVATE KEY-----
)KEY";

const String RSA_PUBLIC_KEY = R"KEY(
-----BEGIN PUBLIC KEY-----
ADD YOUR PUBLIC KEY HERE
-----END PUBLIC KEY-----
)KEY";


#include "Hash.h"
#include "Base64.h"
#include <ArduinoJson.h>

uint8_t _cipher_key[16];

struct EncryptionResult {
  String encrypted_data;
  String encoded_iv;
};
/*END CRYPT CONFIGS**************************************************************/


/*BEGIN SERVER CONFIGS**************************************************************/
#include <ESP8266WiFi.h>
#include <ESP8266HTTPClient.h>
#include <WiFiClient.h>

const char *ssid = "YOUR WIFI CONFIG";
const char *password = "YOUR WIFI CONFIG";

String server_name = "YOUR SERVER CONFIG";
/*END SERVER CONFIGS**************************************************************/


/*BEGIN RELAY CONFIGS**************************************************************/
const int relay = 5;
long count = 0;
unsigned long last_update;
unsigned long now;
/*END RELAY CONFIGS**************************************************************/


/*BEGIN ACS712 CONFIGS**************************************************************/
const int sensorIn = A0;
int mVperAmp = 185;  // use 185 for 5A, 100 for 20A Module and 66 for 30A Module
/*END ACS712 CONFIGS**************************************************************/


/*BEGIN SERVER FUNCS**************************************************************/
String send_payload_server(String url, String json_payload) {
  String response;
  if (WiFi.status() == WL_CONNECTED) {
    WiFiClient client;
    HTTPClient http;
    http.begin(url);
    http.addHeader("Content-Type", "application/json");
    int http_resp_code = http.POST(json_payload);
    if (http_resp_code > 0) {
      Serial.print("HTTP Response code: ");
      Serial.println(http_resp_code);
      response = http.getString();
    } else {
      Serial.print("Error code: ");
      Serial.println(http_resp_code);
      response = "error";
    }
    http.end();
  } else {
    Serial.println("WiFi Disconnected");
    response = "error";
  }
  return response;
}
/*END SERVER FUNCS**************************************************************/


/*BEGIN CRYPT/SERVER FUNCS**************************************************************/
void handshake() {
  String formatted_pub_key = RSA_PUBLIC_KEY;
  formatted_pub_key.replace("\n", "\\n");
  String json_payload = "{\"public_key\":\"" + formatted_pub_key + "\"}";
  String full_url = server_name + "/handshake";
  String response = send_payload_server(full_url, json_payload);
  String encrypted_aes_key = parse_handshake_response(response);
  decrypt_aes_key(encrypted_aes_key);
}

String parse_handshake_response(String response) {
  StaticJsonDocument<512> doc;
  DeserializationError error = deserializeJson(doc, response);
  if (error) {
    Serial.print("Falha ao parsear JSON: ");
    Serial.println(error.f_str());
    return "";
  }
  JsonObject response_obj = doc["response"];
  String encrypted_aes_key = response_obj["encrypted_aes_key"].as<String>();
  return encrypted_aes_key;
}

void decrypt_aes_key(String key_str) {
  int input_len = key_str.length();
  char *key = const_cast<char *>(key_str.c_str());
  int len = base64_dec_len(key, input_len);
  uint8_t data[len];
  base64_decode((char *)data, key, input_len);
  int i;
  BearSSL::PrivateKey *private_key_obj = new BearSSL::PrivateKey(RSA_PRIVATE_KEY);
  (*br_rsa_private_get_default())(data, private_key_obj->getRSA());
  for (i = 2; i < len; i++) {
    if (data[i] == 0) break;
  }
  i++;
  len -= i;
  uint8_t decoded_data[len];
  memcpy(decoded_data, &data[i], len);
  memcpy(_cipher_key, decoded_data, 16);
}

String uint8_to_hex_string(uint8_t *data, size_t length) {
  String hex_str = "";
  for (size_t i = 0; i < length; i++) {
    // Converte o valor do byte para hexadecimal e o adiciona à string
    hex_str += String(data[i], HEX);
    // Se quiser garantir que sempre tenha dois caracteres (em caso de valores abaixo de 0x10)
    if (data[i] < 0x10) {
      hex_str += "0";  // Adiciona um zero à esquerda
    }
  }
  hex_str.toUpperCase();  // Se quiser a string em maiúsculas
  return hex_str;
}

void post_readings_server(float current, float power) {
  String json_payload = "{\"device_id\":\"" + String(DEVICE_ID) + "\","
                                                                  "\"current\":"
                        + String(current) + ","
                                            "\"power\":"
                        + String(power) + "}";

  // Gerar IV aleatório de 16 bytes
  uint8_t iv[16];
  for (int i = 0; i < 16; i++) {
    iv[i] = random(0, 256);  // Gerar número aleatório entre 0 e 255
  }

  String iv_hex = uint8_to_hex_string(iv, 16);

  // Criptografar
  String encrypted_data = aes_128_cbc_encrypt(json_payload, iv);

  // Enviar o resultado ao servidor
  String encrypted_json = "{\"iv\":\"" + iv_hex + "\", \"encrypted_data\":\"" + encrypted_data + "\"}";

  /* DEBUG
    // Testar a descriptografia no cliente com o IV e dados recebidos
    String decrypted_data = aes_128_cbc_decrypt(encrypted_data, iv);
    Serial.println("Decrypted Data: " + decrypted_data);
  */

  // Enviar ao servidor
  String full_url = server_name + "/readings";
  String response = send_payload_server(full_url, encrypted_json);
  Serial.print("Response: ");
  Serial.println(response);
}

String aes_128_cbc_encrypt(String plain_data, uint8_t iv[16]) {
  uint8_t iv_copy[16];
  memcpy(iv_copy, iv, 16);

  // PKCS#7 Padding (Encryption), Block Size: 16
  int len = plain_data.length();
  int n_blocks = len / 16 + 1;
  uint8_t n_padding = n_blocks * 16 - len;
  uint8_t data[n_blocks * 16];
  memcpy(data, plain_data.c_str(), len);

  // Adiciona o padding
  for (int i = len; i < n_blocks * 16; i++) {
    data[i] = n_padding;
  }

  // AES CBC Encryption
  uint8_t key[16];
  memcpy(key, _cipher_key, 16);

  // Contexto de criptografia
  br_aes_big_cbcenc_keys encCtx;

  // Inicializa o contexto de criptografia e criptografa os dados
  br_aes_big_cbcenc_init(&encCtx, key, 16);
  br_aes_big_cbcenc_run(&encCtx, iv_copy, data, n_blocks * 16);

  // Codificar os dados criptografados em hexadecimal
  String hex_data = "";
  for (int j = 0; j < n_blocks * 16; j++) {
    if (data[j] < 0x10) {
      hex_data += "0";
    }
    hex_data += String(data[j], HEX);
  }
  return hex_data;
}

/* DEBUG
  String aes_128_cbc_decrypt(String encoded_data_str, uint8_t iv[16]) {
    uint8_t iv_copy[16];
    memcpy(iv_copy, iv, 16);
    // Base64 Decode para os dados criptografados
    int input_len = encoded_data_str.length();
    char *encoded_data = const_cast<char *>(encoded_data_str.c_str());
    int len = base64_dec_len(encoded_data, input_len);
    uint8_t data[len];
    base64_decode((char *)data, encoded_data, input_len);

    // AES CBC Decryption
    uint8_t key[16];
    memcpy(key, _cipher_key, 16);

    int n_blocks = len / 16;

    br_aes_big_cbcdec_keys decCtx;

    Serial.println("decrypt");
    Serial.println("key");
    for (int j = 0; j < 16; j++) {
      if (key[j] < 0x10) Serial.print("0");
      Serial.println(key[j], HEX);
    }
    Serial.println("");
    Serial.println("iv_copy");
    for (int j = 0; j < 16; j++) {
      if (iv_copy[j] < 0x10) Serial.print("0");
      Serial.println(iv_copy[j], HEX);
    }
    Serial.println("");

    // Inicializa o contexto de decriptação e executa a decriptação
    br_aes_big_cbcdec_init(&decCtx, key, 16);
    br_aes_big_cbcdec_run(&decCtx, iv_copy, data, len);

    // PKCS#7 Padding (Decryption)
    uint8_t n_padding = data[len - 1];
    len = len - n_padding;  // Ajusta o comprimento removendo o padding
    char plain_data[len + 1];
    memcpy(plain_data, data, len);
    plain_data[len] = '\0';  // Finaliza a string

    return String(plain_data);  // Retorna o texto decriptado
  }
*/
/*END CRYPT/SERVER FUNCS**************************************************************/


/*BEGIN RELAY FUNCS**************************************************************/
void turnOnLight() {
  digitalWrite(relay, HIGH);
}

void turnOffLight() {
  digitalWrite(relay, LOW);
}
/*END RELAY FUNCS**************************************************************/


/*BEGIN ACS712 FUNCS**************************************************************/
float getVPP() {
  float voltage;
  int readValue;
  int maxValue = 0;
  int minValue = 1024;
  uint32_t start_time = millis();
  while ((millis() - start_time) < 1000)  //sample for 1 Sec
  {
    readValue = analogRead(sensorIn);
    if (readValue > maxValue) {
      maxValue = readValue;
    }
    if (readValue < minValue) {
      minValue = readValue;
    }
  }
  voltage = ((maxValue - minValue) * 3.3) / 1024.0;
  return voltage;
}

float getCurrent() {
  float current;
  float voltage = getVPP();
  double vRms = (voltage / 2.0) * 0.707;
  current = (vRms * 1000) / mVperAmp;
  return current;
}

float getPower(float current) {
  float power;
  power = (127 * current) - 7;  //Observed 7-10 Watt when no load was connected, so substracting offset value to get real consumption.
  return power;
}

void printSensorReads() {
  float current = getCurrent();
  float power = getPower(current);
  Serial.print("Corrente: ");
  Serial.print(current);
  Serial.println(" A");
  Serial.print("Potência: ");
  Serial.print(power);
  Serial.println(" W");
}
/*END ACS712 FUNCS**************************************************************/


/*BEGIN MAIN FUNCS**************************************************************/
void setup() {

  Serial.begin(115200);

  pinMode(relay, OUTPUT);
  pinMode(A0, INPUT);
  turnOffLight();
  last_update = millis();
  now = millis();

  WiFi.begin(ssid, password);
  Serial.println("Connecting");
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.println("");
  Serial.print("Connected to WiFi network with IP Address: ");
  Serial.println(WiFi.localIP());

  handshake();
}

void loop() {
  now = millis();
  if (millis() - last_update >= 5000) {
    if (count % 2 == 0) {
      turnOffLight();
    } else {
      turnOnLight();
    }
    last_update = now;
    count++;
  }
  float current = getCurrent();
  float power = getPower(current);
  post_readings_server(current, power);
}
/*END MAIN FUNCS**************************************************************/