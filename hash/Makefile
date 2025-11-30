# Makefile для программы хеширования файлов
CXX = g++
CXXFLAGS = -Wall -Wextra -std=c++11 -O2
LDFLAGS = -lcryptopp
TARGET = file_hash
SOURCES = file_hash.cpp

# Основная цель - компиляция программы
$(TARGET): $(SOURCES)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SOURCES) $(LDFLAGS)

# Очистка скомпилированных файлов
clean:
	rm -f $(TARGET)

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
	@echo "=== Тестирование программы хеширования ==="
	@echo "1. Хеширование файла с алгоритмом по умолчанию (SHA-256):"
	./$(TARGET) file1.txt
	@echo ""
	@echo "2. Хеширование с явным указанием алгоритма:"
	./$(TARGET) file1.txt sha512
	@echo ""
	@echo "3. Интерактивный режим (нужно вручную проверить):"
	@echo "Запустите: ./$(TARGET)"

# Показать справку
help:
	@echo "Доступные команды:"
	@echo "  make           - компиляция программы"
	@echo "  make clean     - удаление скомпилированной программы"
	@echo "  make install   - установка в систему"
	@echo "  make debug     - отладочная сборка"
	@echo "  make check-deps - проверка зависимостей"
	@echo "  make test      - запуск тестов"
	@echo "  make help      - показать эту справку"

# Примеры использования после компиляции
examples: $(TARGET)
	@echo "Примеры использования:"
	@echo "  ./$(TARGET) file1.txt                    # SHA-256 по умолчанию"
	@echo "  ./$(TARGET) file1.txt sha512            # Явное указание алгоритма"
	@echo "  ./$(TARGET) file2.txt md5               # MD5 (не рекомендуется)"
	@echo "  ./$(TARGET)                             # Интерактивный режим"

.PHONY: clean install debug check-deps test help examples
