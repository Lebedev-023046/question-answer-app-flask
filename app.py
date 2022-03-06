from tkinter.messagebox import NO
from flask import Flask, redirect, render_template, g, request, session, url_for
from database import get_db
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__)

@app.teardown_appcontext
def close_db(error):
    if hasattr(g, 'sqlite_db'):
        g.sqlite_db.close()

def get_current_user():
    user_result = None
    if 'user' in session:
        user = session['user']
        db = get_db()
        user_cur = db.execute('select id, name, password, admin, expert from users where name = ?', [user])
        user_result = user_cur.fetchone()
    
    return user_result


app.config['ENV'] = 'development'
app.config['SECRET_KEY'] = os.urandom(24)

@app.route('/')
def index():
    user = get_current_user()
    db = get_db()
    question_cur = db.execute('''select 
                                    questions.id as question_id, 
                                    questions.questoin_text, 
                                    askers.name as asker_name, 
                                    experts.name as expert_name
                                 from questions 
                                 join users as askers on askers.id = questions.asked_by_id 
                                 join users as experts on experts.id = questions.expert_id 
                                 where questions.questoin_text is not null''')
    information = question_cur.fetchall()

    return render_template('home.html', user=user, information=information)

@app.route('/register', methods=['GET', 'POST'])
def register():
    user = get_current_user()
    db = get_db()
    if request.method == 'POST':
        name = request.form['name']
        existing_user_cur = db.execute('select id from users where name = ?', [name])
        existing_user = existing_user_cur.fetchone()
        if existing_user:
            return render_template('register.html', user=user, error='User already exists!')

        hashed_passsword = generate_password_hash(request.form['password'], method='sha256')
        db.execute('insert into users (name, password, admin, expert) values (?, ?, ?, ?)', [name, hashed_passsword, '0', '0'])
        db.commit()

        session['user'] = request.form['name']

        return redirect(url_for('index'))
    return render_template('register.html', user=user)

@app.route('/login', methods=['GET', 'POST'])
def login():
    user = get_current_user()
    error = None

    if request.method == "POST":
        name = request.form['name']
        password = request.form['password']
        db = get_db()
        user_cur = db.execute('select id, name, password from users where name = ?', [name])
        user_result = user_cur.fetchone()

        if user_result:
            if check_password_hash(user_result['password'], password):
                session['user'] = user_result['name']
                return redirect(url_for('index'))
            else:
                error = 'Incorrect password!'
        else:
             error =  f'No such user!'
            
    return render_template('login.html', user=user, error=error)

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('index'))

@app.route('/question/<question_id>')
def question(question_id):
    user = get_current_user()
    db = get_db()
    question_cur = db.execute('''select
                                    questions.questoin_text, 
                                    questions.answer_text, 
                                    askers.name as asker_name, 
                                    experts.name as expert_name 
                                from questions 
                                join users as askers on askers.id = questions.asked_by_id 
                                join users as experts on experts.id = questions.expert_id 
                                where questions.id = ?''', [question_id])
    question = question_cur.fetchone()
    return render_template('question.html', user=user, question=question)

@app.route('/answer/<question_id>', methods=['GET', 'POST'])
def answer(question_id):
    user = get_current_user()
    if not user:
        return redirect(url_for('login'))

    if user['expert'] == 0:
        return redirect(url_for('index'))

    db = get_db()
    if request.method == 'POST':
        db.execute('update questions set answer_text = ? where id = ?', [request.form['answer'], question_id])
        db.commit()
        return redirect(url_for('unanswered'))
    question_cur = db.execute('select id, questoin_text from questions where id = ?', [question_id])
    question = question_cur.fetchone()
    return render_template('answer.html', user=user, question=question)

@app.route('/ask', methods=['GET', 'POST'])
def ask():
    user = get_current_user()
    if not user:
        return redirect(url_for('login'))
    db = get_db()
    if request.method == 'POST':
        db.execute('insert into questions (questoin_text, asked_by_id, expert_id) values (?, ?, ?)',
                     [request.form['question'], user['id'], request.form['expert']])
        db.commit()
        return redirect(url_for('index'))
    expert_cur = db.execute('select id, name from users where expert = 1')
    expert_result = expert_cur.fetchall()
    return render_template('ask.html', user=user, expert_result=expert_result)

@app.route('/users')
def users():
    user = get_current_user()

    if not user:
        return redirect(url_for('login'))

    if user['admin'] == 0:
        return redirect(url_for('index'))

    db = get_db()
    users_cur = db.execute('select id, name, expert, admin from users')
    users_result = users_cur.fetchall()

    return render_template('users.html', user=user, users_result=users_result)

@app.route('/promote/<user_id>')
def promote(user_id):
    user = get_current_user()
    if not user:
        return redirect(url_for('login'))
    
    if user['admin'] == 0:
        return redirect(url_for('index'))

    db = get_db()
    db.execute('update users set expert = 1 where id = ?', [user_id])
    db.commit()
    return redirect(url_for('users'))

@app.route('/unanswered')
def unanswered():
    user = get_current_user()

    if not user:
        return redirect(url_for('login'))

    if user['expert'] == 0:
        return redirect(url_for('index'))

    db = get_db()
    questions_cur = db.execute('''select 
                                        questions.id, 
                                        questions.questoin_text, 
                                        questions.asked_by_id, 
                                        users.name 
                                    from questions 
                                    join users on users.id = questions.asked_by_id 
                                    where questions.answer_text is null and questions.expert_id = ?''', [user['id']])
    questions = questions_cur.fetchall()
    return render_template('unanswered.html', user=user, questions=questions)


if __name__ == "__main__":
    app.run(debug=True)