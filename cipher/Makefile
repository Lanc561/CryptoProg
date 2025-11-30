# Makefile для программы шифрования файлов
CXX = g++
CXXFLAGS = -Wall -Wextra -std=c++11 -O2
LDFLAGS = -lcryptopp
TARGET = file_crypto
SOURCES = file_crypto.cpp

# Основная цель - компиляция программы
$(TARGET): $(SOURCES)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SOURCES) $(LDFLAGS)

# Очистка скомпилированных файлов
clean:
	rm -f $(TARGET) *.encrypted *.decrypted *.bin

# Установка в систему
install: $(TARGET)
	cp $(TARGET) /usr/local/bin/
	@echo "Программа установлена в /usr/local/bin/$(TARGET)"

# Отладочная сборка
debug: CXXFLAGS += -g -DDEBUG
debug: $(TARGET)

# Проверка зависимостей
check-deps:
	@echo "Проверка зависимостей..."
	@pkg-config --exists libcrypto++ || echo "ВНИМАНИЕ: Библиотека Crypto++ не установлена"
	@echo "Для установки Crypto++:"
	@echo "  Ubuntu/Debian: sudo apt-get install libcrypto++-dev"
	@echo "  CentOS/RHEL:   sudo yum install cryptopp-devel"
	@echo "  macOS:         brew install cryptopp"

# Тестирование программы
test: $(TARGET)
	@echo "=== Тестирование программы шифрования ==="
	@echo "1. Шифрование файла:"
	./$(TARGET) encrypt aes file1.txt file1_encrypted.bin "testpassword"
	@echo ""
	@echo "2. Расшифрование файла:"
	./$(TARGET) decrypt aes file1_encrypted.bin file1_decrypted.txt "testpassword"
	@echo ""
	@echo "3. Проверка результата:"
	@diff file1.txt file1_decrypted.txt && echo "✅ Файлы идентичны - шифрование работает корректно" || echo "❌ Ошибка: файлы различаются"
	@echo ""
	@echo "4. Интерактивный режим (нужно вручную проверить):"
	@echo "Запустите: ./$(TARGET)"

# Показать справку
help:
	@echo "Доступные команды:"
	@echo "  make           - компиляция программы"
	@echo "  make clean     - удаление скомпилированных файлов"
	@echo "  make install   - установка в систему"
	@echo "  make debug     - отладочная сборка"
	@echo "  make check-deps - проверка зависимостей"
	@echo "  make test      - запуск тестов"
	@echo "  make help      - показать эту справку"

# Примеры использования после компиляции
examples: $(TARGET)
	@echo "Примеры использования:"
	@echo "  Шифрование:"
	@echo "    ./$(TARGET) encrypt aes file.txt encrypted.bin mypassword"
	@echo "    ./$(TARGET) encrypt 3des data.txt data.enc secret123"
	@echo ""
	@echo "  Расшифрование:"
	@echo "    ./$(TARGET) decrypt aes encrypted.bin decrypted.txt mypassword"
	@echo "    ./$(TARGET) decrypt 3des data.enc data_decrypted.txt secret123"
	@echo ""
	@echo "  Интерактивный режим:"
	@echo "    ./$(TARGET)"
	@echo ""
	@echo "Доступные алгоритмы: aes, des, 3des, blowfish"

# Быстрое тестирование с файлом file1.txt
quick-test: $(TARGET)
	@echo "=== Быстрое тестирование шифрования ==="
	./$(TARGET) encrypt aes file1.txt test_encrypted.bin "testpass"
	./$(TARGET) decrypt aes test_encrypted.bin test_decrypted.txt "testpass"
	@diff file1.txt test_decrypted.txt && echo "✅ Тест пройден успешно!" || echo "❌ Тест не пройден"

.PHONY: clean install debug check-deps test help examples quick-test
