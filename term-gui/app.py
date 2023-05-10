#!/usr/bin/python3

from flask import Flask
from flask import request
from flask import render_template

app = Flask(__name__)


@app.route("/", methods=['GET'])
def index():
	return render_template('/static/index.html')


@app.route('/submit', methods=['POST'])
def submit():
    ip = request.form['ip']
    wordlist = request.form['wordlist']
    # run enum.py with ip/wordlist
    return 'Received IP address: ' + ip
    #os.system("python3 enum.py {} {}".format(ip,wordlist))
    results(ip)


@app.route("/results.html")
def results(ip):
	return render_template('/static/results.html')
	return 


'''


	error = None
    if request.method == 'POST':
        if valid_login(request.form['username'],
                       request.form['password']):
            return log_the_user_in(request.form['username'])
        else:
            error = 'Invalid username/password'
    # the code below is executed if the request method
    # was GET or the credentials were invalid
    return render_template('login.html', error=error)
'''

index()
