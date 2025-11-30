#include <iostream>
#include <fstream>
#include <string>
#include <vector>

#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include <cryptopp/cryptlib.h>
#include <cryptopp/aes.h>
#include <cryptopp/des.h>
#include <cryptopp/blowfish.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/sha.h>
#include <cryptopp/osrng.h>

using namespace std;
using namespace CryptoPP;

// Функция для вывода доступных алгоритмов
void ShowAvailableAlgorithms() {
    cout << "Доступные алгоритмы шифрования:" << endl;
    cout << "  aes      - AES (128/192/256 бит) [РЕКОМЕНДУЕМЫЙ]" << endl;
    cout << "  des      - DES (56 бит) [СЛАБЫЙ]" << endl;
    cout << "  3des     - Triple DES (168 бит)" << endl;
    cout << "  blowfish - Blowfish (32-448 бит)" << endl;
    cout << endl;
}

// Функция для получения размера ключа по алгоритму
size_t GetKeySize(const string& algorithm) {
    if (algorithm == "aes") return 32;      // AES-256
    if (algorithm == "3des") return 24;     // 3DES
    if (algorithm == "blowfish") return 16; // Blowfish-128
    if (algorithm == "des") return 8;       // DES
    return 16; // по умолчанию
}

// Функция для получения размера блока по алгоритму
size_t GetBlockSize(const string& algorithm) {
    if (algorithm == "aes") return AES::BLOCKSIZE;
    if (algorithm == "des" || algorithm == "3des") return DES_EDE3::BLOCKSIZE;
    if (algorithm == "blowfish") return Blowfish::BLOCKSIZE;
    return AES::BLOCKSIZE;
}

// Функция для выработки ключа из пароля
void DeriveKey(const string& password, byte* key, size_t key_size, byte* iv, size_t iv_size) {
    byte salt[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    
    // Генерируем ключ из пароля
    PKCS5_PBKDF2_HMAC<SHA256> pbkdf;
    pbkdf.DeriveKey(key, key_size, 0, 
                   reinterpret_cast<const byte*>(password.data()), password.size(),
                   salt, sizeof(salt), 1000);
    
    // Генерируем IV из пароля (упрощенно)
    PKCS5_PBKDF2_HMAC<SHA1> pbkdf_iv;
    pbkdf_iv.DeriveKey(iv, iv_size, 0,
                      reinterpret_cast<const byte*>(password.data()), password.size(),
                      salt, sizeof(salt), 500);
}

// Функция шифрования
bool EncryptFile(const string& input_file, const string& output_file, 
                const string& password, const string& algorithm) {
    try {
        // Читаем исходный файл
        ifstream in_file(input_file, ios::binary);
        if (!in_file) {
            throw runtime_error("Не удалось открыть исходный файл: " + input_file);
        }
        
        vector<byte> plaintext((istreambuf_iterator<char>(in_file)),
                              istreambuf_iterator<char>());
        in_file.close();
        
        // Подготавливаем ключ и IV
        size_t key_size = GetKeySize(algorithm);
        size_t block_size = GetBlockSize(algorithm);
        
        vector<byte> key(key_size);
        vector<byte> iv(block_size);
        DeriveKey(password, key.data(), key_size, iv.data(), block_size);
        
        // Шифруем
        vector<byte> ciphertext;
        
        if (algorithm == "aes") {
            CBC_Mode<AES>::Encryption encryptor;
            encryptor.SetKeyWithIV(key.data(), key_size, iv.data());
            StringSource(plaintext.data(), plaintext.size(), true,
                new StreamTransformationFilter(encryptor,
                    new VectorSink(ciphertext)
                )
            );
        }
        else if (algorithm == "des") {
            CBC_Mode<DES>::Encryption encryptor;
            encryptor.SetKeyWithIV(key.data(), key_size, iv.data());
            StringSource(plaintext.data(), plaintext.size(), true,
                new StreamTransformationFilter(encryptor,
                    new VectorSink(ciphertext)
                )
            );
        }
        else if (algorithm == "3des") {
            CBC_Mode<DES_EDE3>::Encryption encryptor;
            encryptor.SetKeyWithIV(key.data(), key_size, iv.data());
            StringSource(plaintext.data(), plaintext.size(), true,
                new StreamTransformationFilter(encryptor,
                    new VectorSink(ciphertext)
                )
            );
        }
        else if (algorithm == "blowfish") {
            CBC_Mode<Blowfish>::Encryption encryptor;
            encryptor.SetKeyWithIV(key.data(), key_size, iv.data());
            StringSource(plaintext.data(), plaintext.size(), true,
                new StreamTransformationFilter(encryptor,
                    new VectorSink(ciphertext)
                )
            );
        }
        else {
            throw runtime_error("Неизвестный алгоритм: " + algorithm);
        }
        
        // Записываем зашифрованные данные
        ofstream out_file(output_file, ios::binary);
        if (!out_file) {
            throw runtime_error("Не удалось создать выходной файл: " + output_file);
        }
        
        // Добавляем IV в начало файла для последующего расшифрования
        out_file.write(reinterpret_cast<const char*>(iv.data()), iv.size());
        out_file.write(reinterpret_cast<const char*>(ciphertext.data()), ciphertext.size());
        out_file.close();
        
        return true;
        
    } catch (const exception& e) {
        cerr << "Ошибка шифрования: " << e.what() << endl;
        return false;
    }
}

// Функция расшифрования
bool DecryptFile(const string& input_file, const string& output_file,
                const string& password, const string& algorithm) {
    try {
        // Читаем зашифрованный файл
        ifstream in_file(input_file, ios::binary);
        if (!in_file) {
            throw runtime_error("Не удалось открыть зашифрованный файл: " + input_file);
        }
        
        vector<byte> ciphertext((istreambuf_iterator<char>(in_file)),
                               istreambuf_iterator<char>());
        in_file.close();
        
        // Извлекаем IV и зашифрованные данные
        size_t block_size = GetBlockSize(algorithm);
        if (ciphertext.size() < block_size) {
            throw runtime_error("Файл слишком короткий для расшифрования");
        }
        
        vector<byte> iv(ciphertext.begin(), ciphertext.begin() + block_size);
        vector<byte> encrypted_data(ciphertext.begin() + block_size, ciphertext.end());
        
        // Подготавливаем ключ
        size_t key_size = GetKeySize(algorithm);
        vector<byte> key(key_size);
        vector<byte> dummy_iv(block_size); // не используется здесь
        DeriveKey(password, key.data(), key_size, dummy_iv.data(), block_size);
        
        // Расшифровываем
        vector<byte> plaintext;
        
        if (algorithm == "aes") {
            CBC_Mode<AES>::Decryption decryptor;
            decryptor.SetKeyWithIV(key.data(), key_size, iv.data());
            StringSource(encrypted_data.data(), encrypted_data.size(), true,
                new StreamTransformationFilter(decryptor,
                    new VectorSink(plaintext)
                )
            );
        }
        else if (algorithm == "des") {
            CBC_Mode<DES>::Decryption decryptor;
            decryptor.SetKeyWithIV(key.data(), key_size, iv.data());
            StringSource(encrypted_data.data(), encrypted_data.size(), true,
                new StreamTransformationFilter(decryptor,
                    new VectorSink(plaintext)
                )
            );
        }
        else if (algorithm == "3des") {
            CBC_Mode<DES_EDE3>::Decryption decryptor;
            decryptor.SetKeyWithIV(key.data(), key_size, iv.data());
            StringSource(encrypted_data.data(), encrypted_data.size(), true,
                new StreamTransformationFilter(decryptor,
                    new VectorSink(plaintext)
                )
            );
        }
        else if (algorithm == "blowfish") {
            CBC_Mode<Blowfish>::Decryption decryptor;
            decryptor.SetKeyWithIV(key.data(), key_size, iv.data());
            StringSource(encrypted_data.data(), encrypted_data.size(), true,
                new StreamTransformationFilter(decryptor,
                    new VectorSink(plaintext)
                )
            );
        }
        else {
            throw runtime_error("Неизвестный алгоритм: " + algorithm);
        }
        
        // Записываем расшифрованные данные
        ofstream out_file(output_file, ios::binary);
        if (!out_file) {
            throw runtime_error("Не удалось создать выходной файл: " + output_file);
        }
        
        out_file.write(reinterpret_cast<const char*>(plaintext.data()), plaintext.size());
        out_file.close();
        
        return true;
        
    } catch (const exception& e) {
        cerr << "Ошибка расшифрования: " << e.what() << endl;
        return false;
    }
}

// Функция для парсинга аргументов командной строки
bool ParseArguments(int argc, char* argv[], string& mode, string& algorithm, 
                   string& input_file, string& output_file, string& password) {
    mode = "";
    algorithm = "";
    input_file = "";
    output_file = "";
    password = "";
    
    for (int i = 1; i < argc; i++) {
        string arg = argv[i];
        
        if (arg == "-m" || arg == "--mode") {
            if (i + 1 < argc) {
                mode = argv[++i];
            } else {
                cerr << "Ошибка: после параметра " << arg << " должен быть указан режим" << endl;
                return false;
            }
        } else if (arg == "-a" || arg == "--algorithm") {
            if (i + 1 < argc) {
                algorithm = argv[++i];
            } else {
                cerr << "Ошибка: после параметра " << arg << " должен быть указан алгоритм" << endl;
                return false;
            }
        } else if (arg == "-i" || arg == "--input") {
            if (i + 1 < argc) {
                input_file = argv[++i];
            } else {
                cerr << "Ошибка: после параметра " << arg << " должен быть указан входной файл" << endl;
                return false;
            }
        } else if (arg == "-o" || arg == "--output") {
            if (i + 1 < argc) {
                output_file = argv[++i];
            } else {
                cerr << "Ошибка: после параметра " << arg << " должен быть указан выходной файл" << endl;
                return false;
            }
        } else if (arg == "-p" || arg == "--password") {
            if (i + 1 < argc) {
                password = argv[++i];
            } else {
                cerr << "Ошибка: после параметра " << arg << " должен быть указан пароль" << endl;
                return false;
            }
        } else if (arg == "-h" || arg == "--help") {
            cout << "Использование: " << argv[0] << " -m <режим> -a <алгоритм> -i <входной> -o <выходной> -p <пароль>" << endl;
            cout << "Короткие опции:" << endl;
            cout << "  -m, --mode MODE       Режим: encrypt или decrypt" << endl;
            cout << "  -a, --algorithm ALG   Алгоритм шифрования" << endl;
            cout << "  -i, --input FILE      Входной файл" << endl;
            cout << "  -o, --output FILE     Выходной файл" << endl;
            cout << "  -p, --password PASS   Пароль" << endl;
            cout << "  -h, --help            Справка" << endl;
            cout << endl;
            cout << "Примеры:" << endl;
            cout << "  " << argv[0] << " -m encrypt -a aes -i file.txt -o encrypted.bin -p mypass" << endl;
            cout << "  " << argv[0] << " -m decrypt -a aes -i encrypted.bin -o decrypted.txt -p mypass" << endl;
            cout << endl;
            ShowAvailableAlgorithms();
            return false;
        } else {
            // Для обратной совместимости со старым форматом
            if (mode.empty() && i == 1) mode = arg;
            else if (algorithm.empty() && i == 2) algorithm = arg;
            else if (input_file.empty() && i == 3) input_file = arg;
            else if (output_file.empty() && i == 4) output_file = arg;
            else if (password.empty() && i == 5) password = arg;
            else {
                cerr << "Неизвестный параметр: " << arg << endl;
                return false;
            }
        }
    }
    
    // Проверка обязательных параметров
    if (mode.empty()) {
        cerr << "Ошибка: не указан режим работы (-m)" << endl;
        return false;
    }
    if (algorithm.empty()) {
        cerr << "Ошибка: не указан алгоритм (-a)" << endl;
        return false;
    }
    if (input_file.empty()) {
        cerr << "Ошибка: не указан входной файл (-i)" << endl;
        return false;
    }
    if (output_file.empty()) {
        cerr << "Ошибка: не указан выходной файл (-o)" << endl;
        return false;
    }
    if (password.empty()) {
        cerr << "Ошибка: не указан пароль (-p)" << endl;
        return false;
    }
    
    // Валидация режима
    if (mode != "encrypt" && mode != "decrypt") {
        cerr << "Ошибка: неверный режим. Используйте 'encrypt' или 'decrypt'" << endl;
        return false;
    }
    
    return true;
}

void PrintUsage(const char* program_name) {
    cout << "Использование:" << endl;
    cout << "  " << program_name << " -m <режим> -a <алгоритм> -i <входной> -o <выходной> -p <пароль>" << endl;
    cout << "  " << program_name << " <режим> <алгоритм> <входной> <выходной> <пароль>" << endl;
    cout << "  " << program_name << "                     (интерактивный режим)" << endl;
    cout << endl;
    cout << "Параметры:" << endl;
    cout << "  -m, --mode MODE       Режим: encrypt (шифрование) или decrypt (расшифрование)" << endl;
    cout << "  -a, --algorithm ALG   Алгоритм: aes, des, 3des, blowfish" << endl;
    cout << "  -i, --input FILE      Входной файл" << endl;
    cout << "  -o, --output FILE     Выходной файл" << endl;
    cout << "  -p, --password PASS   Пароль для шифрования/расшифрования" << endl;
    cout << "  -h, --help            Справка" << endl;
    cout << endl;
    cout << "Примеры:" << endl;
    cout << "  " << program_name << " -m encrypt -a aes -i file.txt -o file_encrypted.bin -p MyPassword123" << endl;
    cout << "  " << program_name << " -m decrypt -a aes -i file_encrypted.bin -o file_decrypted.txt -p MyPassword123" << endl;
    cout << endl;
    ShowAvailableAlgorithms();
}

int main(int argc, char* argv[]) {
    try {
        cout << "=== Программа шифрования/расшифрования файлов ===" << endl;
        cout << "Режим: CBC, Алгоритм: блочный" << endl << endl;

        // Если есть аргументы командной строки
        if (argc > 1) {
            string mode, algorithm, input_file, output_file, password;
            
            if (!ParseArguments(argc, argv, mode, algorithm, input_file, output_file, password)) {
                PrintUsage(argv[0]);
                return 1;
            }
            
            bool success = false;
            
            if (mode == "encrypt") {
                cout << "Зашифрование..." << endl;
                success = EncryptFile(input_file, output_file, password, algorithm);
                if (success) {
                    cout << "✅ Файл успешно зашифрован!" << endl;
                }
            }
            else if (mode == "decrypt") {
                cout << "Расшифрование..." << endl;
                success = DecryptFile(input_file, output_file, password, algorithm);
                if (success) {
                    cout << "✅ Файл успешно расшифрован!" << endl;
                }
            }
            
            if (!success) {
                throw runtime_error("Операция завершилась с ошибкой");
            }
            
            cout << "Исходный файл: " << input_file << endl;
            cout << "Результирующий файл: " << output_file << endl;
            cout << "Алгоритм: " << algorithm << endl;
            cout << "Режим: " << mode << endl;
            
            return 0;
        }
        // Интерактивный режим (оригинальная логика)
        else if (argc == 1) {
            string mode;
            cout << "Выберите режим работы:" << endl;
            cout << "  1 - Зашифрование" << endl;
            cout << "  2 - Расшифрование" << endl;
            cout << "Ваш выбор (1/2): ";
            getline(cin, mode);
            
            if (mode != "1" && mode != "2") {
                throw runtime_error("Неверный выбор режима");
            }
            
            ShowAvailableAlgorithms();
            string algorithm;
            cout << "Выберите алгоритм шифрования: ";
            getline(cin, algorithm);
            
            string input_file, output_file;
            cout << "Введите путь к исходному файлу: ";
            getline(cin, input_file);
            
            cout << "Введите путь для результата: ";
            getline(cin, output_file);
            
            string password;
            cout << "Введите пароль: ";
            getline(cin, password);
            
            if (password.empty()) {
                throw runtime_error("Пароль не может быть пустым");
            }
            
            bool success = false;
            
            if (mode == "1") {
                cout << endl << "Зашифрование..." << endl;
                success = EncryptFile(input_file, output_file, password, algorithm);
                if (success) {
                    cout << "✅ Файл успешно зашифрован!" << endl;
                }
            } else {
                cout << endl << "Расшифрование..." << endl;
                success = DecryptFile(input_file, output_file, password, algorithm);
                if (success) {
                    cout << "✅ Файл успешно расшифрован!" << endl;
                }
            }
            
            if (!success) {
                throw runtime_error("Операция завершилась с ошибкой");
            }
            
            cout << "Исходный файл: " << input_file << endl;
            cout << "Результирующий файл: " << output_file << endl;
            cout << "Алгоритм: " << algorithm << endl;
            
        }
        else {
            PrintUsage(argv[0]);
            return 1;
        }
        
    } catch (const exception& e) {
        cerr << "Ошибка: " << e.what() << endl;
        PrintUsage(argv[0]);
        return 1;
    }
    
    return 0;
}
