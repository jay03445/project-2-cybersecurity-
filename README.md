#This project extends the JWKS server by using SQLite, and the usage of private keys RSA. The server capabilities are to generate the valid/expired keys, which help advance the JWKS responses.
To run the server: 
py main.py  
To run the gradebot: 
 ./gradebot.exe project-2 --run="py main.py"
To run tests: 
py -m pytest --cov=. --cov-report=term-missing 
