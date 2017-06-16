# Indirmek
wget https://raw.githubusercontent.com/functure/isthisipbad/master/isthisipbad.py

# Kullanım
python isthisipbad.py

./isthisipbad.py

## Yardım
./isthisipbad --help

## IP Argumani ile
./isthisipbad.py -i 10.200.1.15 10.200.1.13

## CSV Tipinde Cikti
./isthisipbad.py -i 10.200.1.15 10.200.1.13 -o csv

## CSV Tipinde Geolocation Iceren Cikti - Detayli (Verbose)
./isthisipbad.py -i 10.200.1.15 10.200.1.13 -o csv -v

## Satır Satır Girdi Vermek
### Girdiler satır satır ayrilir. Girdiye son vermek icin Ctrl+D tuslari kullanilir. Sonra cikti beklenir
./isthisipbad.py -

## Dosyadan Girdi Vermek
./isthisipbad.py - < girdi_dosyasi.txt

## Ornek Girdi Dosyasi
10.200.1.15

10.200.1.13

8.8.8.8

## Dosyaya CSV Formatinda Cikti Almak
./isthisipbad.py -i 10.200.1.15 10.200.1.13 -o csv > cikti_dosyasi.txt

## Yaygin Bir Kullanim (Girdi Dosyasi İcindeki IPler icin CSV Formatli Detayli Cikti Al ve Cikti Dosyasina Kaydet)
./isthisipbad.py -o csv -v - < girdi_dosyasi.txt > cikti_dosyasi.txt



