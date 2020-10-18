import datetime
import os
import re
import smtplib

from flask import Flask, redirect, render_template, request, flash, url_for, escape, send_from_directory
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine, or_, and_, exists as exist
from flask import session as login_session
import string, random
from hashlib import sha256

from flask_wtf import CSRFProtect

from database_setup import Base, Users, Chat, Messages, Reset, Lock

from cryptography.fernet import Fernet
key = b'Nv0PlsUlYqd1X6ViwZ618n7VmPrBcvlayepsOmeVVeQ='
f = Fernet(key)

#print(str(f.decrypt(token).decode('utf-8')))
#byte_akm = bytes(akm.encode('utf-8'))
#token = f.encrypt(byte_akm)


app = Flask(__name__)
app.secret_key = "qyAxbizRZdk_q2mEIrTtGx87"
WTF_CSRF_SECRET_KEY = "sd54asfdSA5DA5SF8WEFS3F5Aiopjj98h5"
csrf = CSRFProtect(app)


app.config.update(
#SESSION_COOKIE_SECURE=True,
SESSION_COOKIE_HTTPONLY=True,
SESSION_COOKIE_SAMESITE='Lax',
)

@app.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy']='default-src \'self\''
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response

engine = create_engine('mysql+mysqldb://akm:password@localhost/msgs')
Base.metadata.bind = engine
#Base.metadata.drop_all()
Base.metadata.create_all(engine)

DBSession = sessionmaker(bind=engine)
session = DBSession()


#if reset_data.link_time > datetime.datetime.now() - datetime.timedelta(minutes=30):

@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        if request.form['user_name']:
            if check_user(escape(request.form["user_name"])):
                user_name = request.form["user_name"]

        if request.form['pass']:
            password = sha256(str(request.form['pass']).encode('utf-8')).hexdigest()
            print(password)
        user_data = session.query(Users).filter_by(username=user_name, password=password).scalar() is not None
        if user_data:
            user_data = session.query(Users).filter_by(username=user_name, password=password).one()
            user_locked = session.query(Lock).filter_by(count=3, user_id=user_data.id).first() is not None
            print(user_locked)
            if user_locked:
                user_locked = session.query(Lock.count, Lock.user_id, Lock.f_time).filter_by(count=3, user_id=user_data.id).first()
                if user_locked.f_time < datetime.datetime.now() - datetime.timedelta(minutes=15):
                    user_reset = session.query(Lock).filter_by(user_id=user_data.id).one()
                    session.delete(user_reset)
                    session.commit()
                else:
                    print('Account locked, try again later')
                    return redirect(url_for('login'))

            if user_data.username and (user_data.active == 'Y'):
                login_session['username'] = user_name
                print("user_data.email: " + user_data.email)
                return redirect('/home')

            elif user_data.username and (user_data.active == 'N'):
                flash("Please activate your account via the link sent to your mail")
                print('Inactive account!')
                return redirect('/login')
            else:
                print('Incorrect Credentials!')

                return redirect('/login')

            # print(user_check)
        else:
            print('No Data')
            flash('Incorrect Credentials')
            user_data = session.query(Users.id).filter_by(username=user_name).one()

            user_locked = session.query(Lock).filter_by(user_id=user_data.id).scalar() is not None
            print("User Lock status: " + str(user_locked))
            user_data = session.query(Users.id).filter_by(username=user_name).one()
            if not user_locked:
                #user_lock = session.query(Lock).filter_by(user_id=user_data.id).one()
                lock_count = Lock(user_id=user_data.id, count=1)
                session.add(lock_count)
                session.commit()
            else:
                lock_user = session.query(Lock).filter_by(user_id=user_data.id).one()
                lock_user.count += 1
                session.commit()

            return redirect('/login')


    if request.method == 'GET':
        if 'username' in login_session:
            return redirect(url_for('home'))

        return render_template('login.html', login_session=login_session)


@app.route('/')
@app.route('/home', methods=['POST', 'GET'])
def home():
    if request.method == 'GET':
        if 'username' not in login_session:
            return redirect('/login')
        else:
            print("Login user name: " + str(login_session['username']))
            logged_user = session.query(Users).filter_by(username=login_session['username']).one()
            print(logged_user.id)

            return render_template('home.html', login_session=login_session)

    if request.method == 'POST':
        return render_template('home.html', login_session=login_session)


@app.route('/register', methods=['POST', 'GET'])
def register():
    if request.method == 'POST':
        if request.form['user'] and request.form['email']:
            print("username before check: " + request.form['user'])
            if check_user(escape(request.form["user"])):
                user_name = request.form["user"]


            email = escape(request.form['email'])
            user_email = sha256(str(email).encode('utf-8')).hexdigest()
            mail_exist = session.query(Users.email).filter_by(email=user_email).scalar() is not None

            print('Email: ' + str(user_email))
        if request.form['password1'] == request.form['password2']:

            if check_pass(request.form['password1']):
                password = sha256(str(request.form['password1']).encode('utf-8')).hexdigest()

                print(password)
                try:
                    if mail_exist:
                        print('mail already exist, try to login')
                        return redirect(url_for('login'))
                    else:
                        fname = escape(request.form['fname'])
                        lname = escape(request.form['lname'])
                        new_user = Users(username=user_name, email=user_email, password=password, fname=fname, lname=lname)
                        session.add(new_user)
                        session.commit()
                        print('user added!!!!!!')
                        user_link = session.query(Users).filter_by(email=user_email).one()



                    try:
                        sendmail(email, user_link.act_link, purpose='activate')
                    except:
                        print('failed to query mail!!!')

                    return redirect(url_for('login'))
                except:
                    flash('Check all required fields')
                    return redirect(url_for('register'))
            else:
                flash('Password not complex')
                return redirect(url_for('register'))
        else:
            flash('Passwords didn\'t match!!')
            return redirect(url_for('register'))



    return render_template('register.html')

@app.route('/checkpoint/<string:id>')
def checkpoint(id):
    user = session.query(Users).filter_by(act_link=str(id)).one()
    print(user.act_link)
    if user.act_link == id:
        session.query(Users).filter_by(act_link=id).update({'active': 'Y', 'act_link': ''})
        session.commit()
        print('Account activated')
        return redirect(url_for('login'))
    else:
        flash("Inavlid activation Link!")
        return redirect(url_for('login'))

@app.route('/change_password', methods=['POST', 'GET'])
def chgpass():
    if login_session['username']:
        if request.method == 'POST':
            if request.form['oldpass']:
                if (request.form['pass1'] == request.form['pass2']):
                    if check_pass(request.form['pass1']):
                        user = session.query(Users).filter_by(username=login_session['username']).one()
                        if sha256(str(request.form['oldpass']).encode('utf-8')).hexdigest() == user.password:
                            session.query(Users).filter_by(username=login_session['username']).update({'password': sha256(str(request.form['pass1']).encode('utf-8')).hexdigest()})
                            session.commit()
                            flash('Password Changed Successfully')
                            print('Password Changed Successfully')
                            return redirect(url_for('chgpass'))
                        else:
                            flash('Current password is not correct')
                            return redirect(url_for('chgpass'))
                    else:
                        flash('Please use secure complex password')
                        return redirect(url_for('chgpass'))
                else:
                    flash('unmatched new password, please retype it correctly')
                    return redirect(url_for('chgpass'))
            else:
                flash('you must enter current password')
                return redirect(url_for('chgpass'))

        if request.method == 'GET':
            return render_template('change_pass.html')



@app.route('/send', methods=['POST', 'GET'])
def send():
    if request.method == 'POST':

        if 'username' not in login_session:
            return redirect('/login')
        if request.form['receiver']:
            receiver_name = escape(request.form['receiver'])
        else:
            return render_template('send.html')
        if request.form['msg']:
            msg = escape(request.form['msg'])
            msg = f.encrypt(bytes(msg.encode('utf-8')))
        else:
            return render_template('send.html')
        from_user = session.query(Users).filter_by(username=login_session['username']).one()
        print(from_user.id)
        try:
            to_user = session.query(Users).filter_by(username=receiver_name).one()
            print(to_user.id)
        except Exception as e:
            print(e)
            return render_template('send.html')
        try:
            exist1 = session.query(Chat.from_id, Chat.to_id).filter_by(from_id=from_user.id,
                                                                       to_id=to_user.id).scalar() is not None
            exist2 = session.query(Chat.from_id, Chat.to_id).filter_by(from_id=to_user.id,
                                                                       to_id=from_user.id).scalar() is not None

            print(exist1, exist2)
            if (exist1 == False) and (exist2 == False):
                new_chat = Chat(from_id=from_user.id, to_id=to_user.id)
                session.add(new_chat)
                session.commit()
                print("New chat created.")


        except Exception as e:
            print('Error here!!')
            return print(e)
            # redirect('/send')
        print('before new msg')
        chat_info = session.query(Chat).filter(or_(Chat.from_id == from_user.id, Chat.to_id == from_user.id)).one()
        # chat_info = session.query(Chat.id).filter_by(from_id=from_user.id, to_id=to_user.id).one()
        new_msg = Messages(chat_id=chat_info.id, sender_id=from_user.id, msg_body=msg)
        session.add(new_msg)
        session.commit()
        print('New messages added!')
        return redirect(url_for('chat_user', id=chat_info.id))

    if request.method == 'GET':
        if 'username' not in login_session:
            return redirect('/login')
        return render_template('send.html')
    return render_template('send.html')


@app.route('/read', methods=['POST', 'GET'])
def read():
    if request.method == "GET":
        if login_session['username']:
            user_id = session.query(Users.id).filter_by(username=login_session['username']).one()

            exist = session.query(Chat).filter(or_(Chat.from_id == user_id, Chat.to_id == user_id)).scalar() is not None

            if exist == False:
                print("You don't have chats yet")
                return redirect('/home')
            chats = session.query(Chat).filter(or_(Chat.from_id == user_id, Chat.to_id == user_id)).all()

            results = [r.__dict__ for r in chats]
            print(len(results))
            my_chats = {}
            for x in range(0, len(results)):
                print('CHAT_ID: ' + str(results[x]['id']) + '\n')
                my_chats_id = results[x]['id']
                if results[x]['from_id'] == user_id.id:
                    chat_user = session.query(Users.username).filter_by(id=results[x]['to_id']).one()
                    my_chats[my_chats_id] = chat_user.username
                elif results[x]['to_id'] == user_id.id:
                    chat_user = session.query(Users.username).filter_by(id=results[x]['from_id']).one()
                    my_chats[my_chats_id] = chat_user.username
                #print(chat_user)
                print(my_chats)




            return render_template('msgs.html', login_session=login_session, chats=my_chats)
    return "Returned!!"

@app.route('/read/<int:id>', methods=['GET', 'POST'])
def chat_user(id):
    if login_session['username']:
        if request.method == 'POST':
            if request.form['msg']:
                msg = escape(request.form['msg'])
                msg = f.encrypt(bytes(msg.encode('utf-8')))
                sender = session.query(Users.id).filter_by(username=login_session['username']).one()
                sender_id = sender.id
                new_msg = Messages(chat_id=id, sender_id=sender_id, msg_body=msg)
                session.add(new_msg)
                session.commit()
        chat_msgs = session.query(Messages).filter_by(chat_id=id).order_by(Messages.create_time).all()
        results = [r.__dict__ for r in chat_msgs]
        msgs = []
        for x in range(0, len(results)):
            sender_id = results[x]['sender_id']
            print(sender_id)
            sender = session.query(Users.username).filter_by(id=sender_id).one()
            print(results[x]['msg_body'])
            msg_body = str(f.decrypt(bytes(results[x]['msg_body'], encoding='utf-8')).decode('utf-8'))
            print(msg_body)
            msgs.append([sender.username, msg_body])

        return render_template('msgs.html', login_session=login_session, msgs=msgs, chat_id=id)


@app.route('/logout', methods=['GET', 'POST'])
def logout():
    if login_session['username']:

        #del login_session['email']
        del login_session['username']
        login_session.clear()
        return redirect('home')
    else:
        print('can not del session data')
        return redirect('home')


@app.route('/forget', methods=['GET', 'POST'])
def forget():
    if request.method == 'GET':
        return render_template('forget.html')
    if request.method == 'POST':
        if request.form['mail']:
            email = request.form['mail']
            email_hash = sha256(str(email).encode('utf-8')).hexdigest()
            print(email_hash)
            print(email)
            mail_exist = session.query(Users.email).filter_by(email=email_hash).scalar() is not None
            if mail_exist:
                user_id = session.query(Users.id).filter_by(email=email_hash).one()
                reset_random = ''.join(random.choice(string.ascii_uppercase + string.digits + string.ascii_lowercase) for x in range(64))

                old_reset = session.query(Reset).filter_by(user_id=user_id).scalar() is not None
                if old_reset:
                    session.query(Reset).filter_by(user_id=user_id).update({'hash_link': reset_random})
                    session.commit()
                else:
                    reset_row = Reset(user_id=user_id, hash_link=reset_random)
                    session.add(reset_row)
                    session.commit()
                sendmail(email, reset_random, purpose='reset')
                return render_template('forget.html', sent=True)
            else:
                return render_template('forget.html', sent=False)
                print('Sorry, This mail not registered yet!')


@app.route('/reset/<string:id>', methods=['GET', 'POST'])
def reset(id):

    link_exist = session.query(Reset).filter_by(hash_link=id).scalar() is not None
    if link_exist:
        reset_data = session.query(Reset).filter_by(hash_link=id).one()
        print(reset_data.link_time)
        print(datetime.datetime.now())
        print(datetime.timedelta(minutes=30))
        if reset_data.link_time > datetime.datetime.now() - datetime.timedelta(minutes=30):
            if request.method == 'GET':
                return render_template('reset.html')
            if request.method == 'POST':
                if request.form['password1'] == request.form['password2']:
                    if check_pass(request.form['password1']):
                        session.query(Users).filter_by(id=reset_data.user_id).update({'password': sha256(str(request.form['password1']).encode('utf-8'))})
                        session.commit()
                        return redirect(url_for('login'))
                    else:
                        print('Weak Password')
                        return redirect(url_for('reset', id=id))
        else:
            return render_template('forget.html', expired=True)
    else:
        return render_template('forget.html', exist=False)


        
@app.route('/dbdump')
def dump():
    tmp = os.system("mysqldump --compact --no-create-db --skip-triggers --no-create-info msgs > msgs.sql; tar -czvf dump.tar.gz msgs.sql")
    return render_template("dbdump.html", filename="dump.tar.gz")

@app.route("/dbdump/<filename>")
def download(filename):
    return send_from_directory(".", filename)



def check_pass(password):
    strength = 0
    regex = re.compile('[@_!#$%^&*()<>?/\|}{~:]')
    if len(password) >= 8:

        print(password)
        if any(char.islower() for char in password):
            strength +=1
            print(strength)
        if any(char.isupper() for char in password):
            strength +=1
            print(strength)
        if any(char.isdigit() for char in password):
            strength +=1
            print(strength)
        if regex.search(password):
            strength += 1
            print(strength)
    print(strength)
    if strength >= 3 :
        return True
    else:
        return False

def check_user(user):
    if re.match("^[A-Za-z]+.*", user) and (len(user) >= 4):
        regex = re.compile('[@!#$%^&*()<>?/\|}{~:]')
        if (regex.search(user) == None):
            return True
        else:
            flash('username can not contain special characters !')
            return False
    else:
        flash("Username have certain characters that is not allowed !")
        return False

def sendmail(mail, hash, purpose):

    gmail_user = 'your_GMail_account'
    gmail_password = 'Your_Mail_Password'

    sent_from = gmail_user
    to = mail

    if purpose == 'reset':
        subject = 'SecureChat Password Reset Instructions'
        body = 'Hello,\nTo reset your SecureChat account password use the following link:\n\n' \
               'http://localhost:5000/reset/'+hash+'\n\n' \
                'If you did not request a reset, kindly ignore that mail.\n' \
                'Notice: The link is only valid for 30 minute.\nThanks'

    if purpose == 'activate':
        subject = 'SecureChat Activation Instructions'
        body = 'Hello,\nTo activate your SecureChat account please use the following link:\n\n' \
               'http://localhost:5000/checkpoint/' + hash + '\n\n' \
                                                       '\nThanks'

    email_text =  'Subject: {}\n\n{}'.format(subject, body)

    try:
        server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
        server.ehlo()
        server.login(gmail_user, gmail_password)
        server.sendmail(sent_from, to, email_text)
        server.close()

        print('Email sent!')
    except:
        print('Something went wrong...')
    #return "test mail"

if __name__ == '__main__':
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
