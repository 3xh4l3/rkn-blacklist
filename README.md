# rkn-blacklist
Инструменты для работы с единым реестром запрещенных сайтов (https://eais.rkn.gov.ru)

### xml-parser.py

#### Что делает?

Разбирает дамп реестра, полученный в соответствии с памяткой для операторов связи http://vigruzki.rkn.gov.ru/docs/description_for_operators_actual.pdf

Генерирует следующие файлы:

*http_url.txt        - for check and DPI block
*http_ip.txt         - for IP block (porblem URL)
*http_domains.txt    - for DNS block (problem URL)
*https_url.txt       - for check (not blocking)
*https_ip            - for IP block (backup mode)
*https_domains.txt   - for DNS block
*domains.txt         - for statistic
*blocked_ip.txt      - for IP block (type=ip)
*blocked_domains.txt - for DNS block (type=domain)
