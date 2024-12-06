# Управление учетными записями доменов

Это консольное приложение на Go для управления учетными записями доменов с возможностью создания, поиска и удаления аккаунтов. Приложение генерирует безопасные пароли и сохраняет данные в YAML-файле.

## Возможности

- Создание учетных записей: Генерация новых аккаунтов с уникальными паролями.
- Поиск учетных записей: Поиск и отображение аккаунтов по доменному имени.
- Удаление учетных записей: Удаление отдельных аккаунтов или всех аккаунтов домена.
- Генерация паролей: Автоматическая генерация безопасных паролей заданной длины.
- Хранение данных: Сохранение данных аккаунтов в YAML-файле для удобства и простоты использования.

## Установка

 1. Клонируйте репозиторий:

```
git clone https://github.com/hard-gainer/pswd-gen
```
 2. Перейдите в директорию проекта:

``` 
cd yourproject 
```

 3. Соберите приложение:
```
go build -o accountmanager
```

 4. (Опционально) Установите приложение в систему:
```
sudo mv accountmanager /usr/local/bin/ 
```
## Настройка

Перед использованием приложения необходимо установить переменную окружения PSWD_CFG, которая указывает путь к конфигурационному файлу passwords.yaml. Это файл, в котором будут храниться данные ваших аккаунтов.

Установка переменной окружения с использованием Zsh:

1. Откройте файл конфигурации Zsh:

```
nano ~/.zshrc
```

2. Добавьте следующую строку, заменив /путь/к/вашей/папке/passwords.yaml на фактический путь, где вы хотите хранить файл:

```
export PSWD_CFG="/путь/к/вашей/папке/passwords.yaml"
```

Если вы используете WSL2 и хотите хранить файл в папке Documents на Windows, путь может выглядеть так:

```
export PSWD_CFG="/mnt/c/Users/ВашеИмяПользователя/Documents/passwords.yaml"
```

3. Сохраните изменения и закройте файл.

4. Примените изменения:

```
source ~/.zshrc
```

5. Проверьте, что переменная окружения установлена:

```
echo $PSWD_CFG
```

Вы должны увидеть путь к вашему конфигурационному файлу.

Теперь приложение будет использовать указанный вами путь для хранения и чтения данных аккаунтов.

## Использование

Приложение предоставляет несколько команд для управления учетными записями:

- Создание нового аккаунта
```
    accountmanager -c
```
Response:
```
    Write a domain name: example.com
    Write an email: user@example.com
    Added new domain: {Email:user@example.com Password:Abc123!@#}
```

- Поиск аккаунтов по домену
```
    accountmanager -f example.com
```
Response:
```
    [{Email:user@example.com Password:Abc123!@#}]
```

- Удаление аккаунтов
```
    accountmanager -d example.com
```
Response:
```
    Select accounts to delete:
    [ ] user@example.com
```