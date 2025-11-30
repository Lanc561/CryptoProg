#include <iostream>
#include <fstream>
#include <string>
#include <vector>

// Определяем макрос для использования слабых алгоритмов
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1

#include <cryptopp/cryptlib.h>
#include <cryptopp/sha.h>
#include <cryptopp/sha3.h>
#include <cryptopp/md5.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>

using namespace std;
using namespace CryptoPP;

// Функция для вычисления хеша файла с использованием выбранного алгоритма
string CalculateFileHash(const string& filename, const string& algorithm) {
    try {
        ifstream file(filename, ios::binary);
        if (!file) {
            throw runtime_error("Не удалось открыть файл: " + filename);
        }

        // Выбор алгоритма хеширования
        HashTransformation* hash = nullptr;
        
        if (algorithm == "sha1") {
            hash = new SHA1;
        } else if (algorithm == "sha256") {
            hash = new SHA256;
        } else if (algorithm == "sha512") {
            hash = new SHA512;
        } else if (algorithm == "sha3-256") {
            hash = new SHA3_256;
        } else if (algorithm == "sha3-512") {
            hash = new SHA3_512;
        } else if (algorithm == "md5") {
            hash = new Weak::MD5;  // Используем Weak:: для MD5
        } else {
            throw runtime_error("Неизвестный алгоритм: " + algorithm);
        }

        // Вычисление хеша
        string digest;
        FileSource file_source(filename.c_str(), true, 
            new HashFilter(*hash, new HexEncoder(new StringSink(digest))));

        delete hash;
        return digest;

    } catch (const exception& e) {
        throw runtime_error("Ошибка при вычислении хеша: " + string(e.what()));
    }
}

// Функция для отображения доступных алгоритмов
void ShowAvailableAlgorithms() {
    cout << "Доступные алгоритмы хеширования:" << endl;
    cout << "  sha1      - SHA-1 (160 бит) [СЛАБЫЙ]" << endl;
    cout << "  sha256    - SHA-256 (256 бит) [РЕКОМЕНДУЕМЫЙ]" << endl;
    cout << "  sha512    - SHA-512 (512 бит) [СИЛЬНЫЙ]" << endl;
    cout << "  sha3-256  - SHA3-256 (256 бит) [СОВРЕМЕННЫЙ]" << endl;
    cout << "  sha3-512  - SHA3-512 (512 бит) [СОВРЕМЕННЫЙ]" << endl;
    cout << "  md5       - MD5 (128 бит) [ОЧЕНЬ СЛАБЫЙ - только для тестов]" << endl;
    cout << endl;
    cout << "Рекомендации:" << endl;
    cout << "- Для безопасности используйте SHA-256, SHA-512 или SHA3" << endl;
    cout << "- MD5 и SHA-1 не рекомендуются для криптографических целей" << endl;
    cout << endl;
}

// Функция для получения рекомендации по алгоритму
string GetAlgorithmRecommendation(const string& algorithm) {
    if (algorithm == "md5" || algorithm == "sha1") {
        return "ВНИМАНИЕ: Этот алгоритм считается ненадежным для безопасности!";
    } else if (algorithm == "sha256" || algorithm == "sha512" || 
               algorithm == "sha3-256" || algorithm == "sha3-512") {
        return "Этот алгоритм рекомендуется для использования.";
    }
    return "";
}

// Функция для парсинга аргументов командной строки
bool ParseArguments(int argc, char* argv[], string& filename, string& algorithm) {
    filename = "";
    algorithm = "sha256"; // значение по умолчанию
    
    for (int i = 1; i < argc; i++) {
        string arg = argv[i];
        
        if (arg == "-f" || arg == "--file") {
            if (i + 1 < argc) {
                filename = argv[++i];
            } else {
                cerr << "Ошибка: после параметра " << arg << " должен быть указан файл" << endl;
                return false;
            }
        } else if (arg == "-a" || arg == "--algorithm") {
            if (i + 1 < argc) {
                algorithm = argv[++i];
            } else {
                cerr << "Ошибка: после параметра " << arg << " должен быть указан алгоритм" << endl;
                return false;
            }
        } else if (arg == "-h" || arg == "--help") {
            cout << "Использование: " << argv[0] << " [ОПЦИИ]" << endl;
            cout << "Опции:" << endl;
            cout << "  -f, --file FILE       Указать файл для хеширования (обязательно)" << endl;
            cout << "  -a, --algorithm ALG   Указать алгоритм хеширования (по умолчанию: sha256)" << endl;
            cout << "  -h, --help            Показать эту справку" << endl;
            cout << endl;
            ShowAvailableAlgorithms();
            return false;
        } else {
            // Если параметр не распознан, считаем его файлом (для обратной совместимости)
            if (filename.empty()) {
                filename = arg;
            } else if (algorithm == "sha256") {
                // Если алгоритм еще не меняли, считаем второй параметр алгоритмом
                algorithm = arg;
            } else {
                cerr << "Неизвестный параметр: " << arg << endl;
                return false;
            }
        }
    }
    
    if (filename.empty()) {
        cerr << "Ошибка: не указан файл для хеширования" << endl;
        return false;
    }
    
    return true;
}

int main(int argc, char* argv[]) {
    try {
        cout << "=== Программа хеширования файлов ===" << endl;
        cout << "Используется библиотека Crypto++" << endl << endl;

        // Если есть аргументы командной строки
        if (argc > 1) {
            string filename, algorithm;
            
            if (!ParseArguments(argc, argv, filename, algorithm)) {
                cerr << "Использование: " << endl;
                cerr << "  " << argv[0] << " -f <файл> [-a <алгоритм>]" << endl;
                cerr << "  " << argv[0] << " <файл> <алгоритм>" << endl;
                cerr << "  " << argv[0] << " <файл>              (использует SHA-256 по умолчанию)" << endl;
                cerr << "  " << argv[0] << " -h                  (справка)" << endl;
                cerr << "  " << argv[0] << "                     (интерактивный режим)" << endl;
                return 1;
            }
            
            string hash = CalculateFileHash(filename, algorithm);
            cout << "Файл: " << filename << endl;
            cout << "Алгоритм: " << algorithm << endl;
            cout << "Хеш: " << hash << endl;
            cout << "Длина хеша: " << hash.length() << " символов" << endl;
            cout << GetAlgorithmRecommendation(algorithm) << endl;
            
        } else {
            // Интерактивный режим
            ShowAvailableAlgorithms();

            string filename, algorithm;
            
            cout << "Введите путь к файлу: ";
            getline(cin, filename);
            
            cout << "Введите алгоритм хеширования: ";
            getline(cin, algorithm);

            // Если алгоритм не указан, используем SHA-256 по умолчанию
            if (algorithm.empty()) {
                algorithm = "sha256";
                cout << "Используется алгоритм по умолчанию: " << algorithm << endl;
            }

            string hash = CalculateFileHash(filename, algorithm);
            string recommendation = GetAlgorithmRecommendation(algorithm);
            
            cout << endl << "Результат хеширования:" << endl;
            cout << "=================================" << endl;
            cout << "Файл: " << filename << endl;
            cout << "Алгоритм: " << algorithm << endl;
            cout << "Хеш: " << hash << endl;
            cout << "Длина хеша: " << hash.length() << " символов" << endl;
            if (!recommendation.empty()) {
                cout << recommendation << endl;
            }
            cout << "=================================" << endl;
        }

    } catch (const exception& e) {
        cerr << "Ошибка: " << e.what() << endl;
        cerr << "Использование: " << endl;
        cerr << "  " << argv[0] << " -f <файл> [-a <алгоритм>]" << endl;
        cerr << "  " << argv[0] << " <файл> <алгоритм>" << endl;
        cerr << "  " << argv[0] << " <файл>              (использует SHA-256 по умолчанию)" << endl;
        cerr << "  " << argv[0] << " -h                  (справка)" << endl;
        cerr << "  " << argv[0] << "                     (интерактивный режим)" << endl;
        return 1;
    }

    return 0;
}
