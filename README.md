# Odhum
"Odhum" named after famous **Punjabi** hero Odhum Singh who killed Dyre in vengeance of "Jallianwala Bagh massacre".
Odhum is **Online Hash checker** from **Virus Total** and **OTX** in Bulk. This can calculate most common hash types from given directory and scan those hashes automatically.
Apart from calculation it can read hashes from TXT and it's own created XLSX file. 
Pretty strict on commandline arguments. 

usage: odhum.py [-h] [-f INPUT_FILE] [-d INPUT_PATH] [--algo ALGO]
               [-o OUTPUT_FILE] [-m MODE]

optional arguments:
  -h, --help            show this help message and exit
  -f INPUT_FILE, --file INPUT_FILE
                        Provide Exact Path for Text or CSV file to read hashes
                        from.
  -d INPUT_PATH         Provide Directory that you want to traverse for hash
                        calculation.
  --algo ALGO           Algorithm to calculate hash possible algos
                        [md5,sha1,sha256]
  -o OUTPUT_FILE, --output OUTPUT_FILE
                        OutPut file Path. Make sure you have permission to
                        write.
  -m MODE, --mode MODE  Possible mode are [save,scan,auto]
  
  Currently only accepts input file in form of txt and it's own generated xlsx file. 
  Odhum supports [md5,sha1,sha256] algos but if you don't provide any algo it will select MD5 as defaut.
  
  For usage clone whole repo and provide you OTX and VT API keys in config.ini file. Config file must be in the same directory where odhum is running from. 
  
  Common Usage:
  1. For hash calculation and scanning at the same time.
     
     odhum.py -d E:\malwares -o E:\output.xlsx -m auto --algo sha256   --only support xlsx output format.
     
     --auto mode will calculate hashes first and then check those hashes automatically.
     
  2. For Hashes calculation only, incase you want to scan later.


     odhum.py -d E:\malwares -o E:\output.xlsx -m save --algo md5   --will only calculate hashes along with file names. 
     
  3. Scan Already created files. It can only scan file in it's own format.
  
  
     odhum.py -f E:\malwares.xlsx -o E:\results.xlsx -m scan
     
 4. TXT file scanning, results will be saved into xlsx file provided in command line.


     odhum.py -f E:\malwares.txt -o E:\results.xlsx -m scan
   
   i Auto Mode will calculate and scan hashes.
   ii save mode will only calculate hases
   iii scan mode will read input from given file and check for reputation.
     
     
 Further Threat Intelligence output will be added in future.
     
   Incase of an issue or error send me an email at:
   mianmajid432@gmail.com
     
