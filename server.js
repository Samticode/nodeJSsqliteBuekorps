const express = require('express');
const session = require('express-session');
const path = require('path');
const sqlite3 = require('better-sqlite3');
const bcrypt = require('bcrypt');
const dotenv = require('dotenv');
dotenv.config()
const methodOverride = require('method-override');


//------------------------------CONFIGURATIONS AND VARIABLES----------------------------------
    
    
const app = express();

const db = new sqlite3('./database/buekorps.db', { verbose: console.log });

const mainFolder = path.join(__dirname, 'public');
app.use(express.static(mainFolder));

const loginFolder = path.join(mainFolder, 'login');
const signupFolder = path.join(mainFolder, 'signup');
const adminFolder = path.join(mainFolder, 'admin');
const leaderFolder = path.join(mainFolder, 'leader');
const memberFolder = path.join(mainFolder, 'member');


app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(methodOverride('_method'));

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false
}))

const saltRounds = 10


//---------------------------FUNCTION TO CHECK AUTHORITY LEVEL-------------------------------------


const checkAuthorization = (allowedRoles) => {
  return (req, res, next) => {
    if (!req.session.loggedIn) {
      return res.redirect('/login');
    }

    if (!allowedRoles.includes(req.session.userRole)) {
      return res.status(403).send('<p style="font-size:12rem;">Ikke snok din rotte</p>');
    }

    next();
  };
};


//---------------------------LOGIN AND ROUTING-------------------------------------


app.get('/', (req, res) => {
  res.redirect('/login');
});

app.get('/login', (req, res) => {
    res.send(loginFolder);
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  const query = `SELECT user_id, username, password_hash, role, email, peleton_id FROM users WHERE username = ?;`;
  const statement = db.prepare(query);
  const userData = statement.get(username);

  req.session.userId = userData.user_id;
  req.session.username = userData.username;
  req.session.userEmail = userData.email;

  if (userData) {
    try {
      const passwordMatch = await bcrypt.compare(password, userData.password_hash);

      if (passwordMatch) {
        req.session.userRole = userData.role;
        req.session.loggedIn = true;

        switch (req.session.userRole) {
          case 'admin':
            res.redirect('/main/admin');
            break;
          case 'leader':
            res.redirect('/main/leader');
            break;
          case 'member':
            res.redirect('/main/member');
            break;
          default:
            req.session.loggedIn = false;
            res.redirect('/login');
        }
      } else {
        req.session.loggedIn = false;
        res.redirect('/login');
      }
    } catch (error) {
      console.error('Error comparing passwords:', error);
      res.status(500).send('Internal Server Error');
    }
  } else {
    req.session.loggedIn = false;
    res.redirect('/login');
  }

});

app.get('/signup', (req, res) => {
  res.send(signupFolder);
});

app.post('/signup', async (req, res) => {
  const { username, password, email } = req.body;
  let { role } = req.body;

  role = role.toLowerCase(); // Convert role to lowercase

  const existingUser = db.prepare('SELECT * FROM users WHERE username = ?').get(username);

  if (existingUser) {
    return res.status(409).send('Brukernavnet eksisterer allerede.');
  }

  const hashedPassword = await bcrypt.hash(password, saltRounds);

  const query = `INSERT INTO users (username, password_hash, role, email) VALUES (?, ?, ?, ?);`;
  const statement = db.prepare(query);
  statement.run(username, hashedPassword, role, email);

  res.redirect('/login');
});


// ------------------


app.get('/main/admin', checkAuthorization(['admin']), (req, res) => {
  res.sendFile(path.join(adminFolder, 'index.html'));
  console.log("Reached admin route");
});

app.get('/main/leader', checkAuthorization(['leader']), (req, res) => {
  res.sendFile(path.join(leaderFolder, 'index.html'));
  console.log("Reached leader route");
});

app.get('/main/member', checkAuthorization(['member']), (req, res) => {
  res.sendFile(path.join(memberFolder, 'index.html'));
  console.log("Reached member route");
});

//-----------------------------API-----------------------------------

app.get('/api/users', (req, res) => {
  const query = `
  SELECT u.user_id, u.username, u.password_hash, u.role, u.email,
  p.peleton_id, p.name AS peleton_name,
  c.company_id, c.name AS company_name, c.user_id AS leader_id, cu.username AS leader_name, cu.email AS leader_email
  FROM users u
  INNER JOIN peletons p ON u.peleton_id = p.peleton_id
  INNER JOIN companys c ON p.company_id = c.company_id
  INNER JOIN users cu ON c.user_id = cu.user_id
  `;
  
  const usersSqlite = db.prepare(query).all();
  res.json(usersSqlite);
});

app.get('/api/peletons', (req, res) => {
  const query = `
  SELECT p.peleton_id, p.name AS peleton_name, 
  c.company_id, c.name AS company_name, c.user_id AS leader_id, 
  cu.username AS leader_name
  
  FROM peletons p
  INNER JOIN companys c ON p.company_id = c.company_id
  LEFT JOIN users cu ON c.user_id = cu.user_id;
  `;
  
  const peletonsSqlite = db.prepare(query).all();
  res.json(peletonsSqlite);
});

app.get('/api/companys', (req, res) => {
  const query = `
  SELECT c.company_id, c.name AS company_name, c.user_id AS leader_id, 
  u.username AS leader_name
  FROM companys c
  LEFT JOIN users u ON c.user_id = u.user_id
  `;
  
  const companysSqlite = db.prepare(query).all();
  res.json(companysSqlite);
});

app.get('/api/leaders', (req, res) => {
  const query = `
  SELECT username, user_id
  FROM users
  WHERE role = 'leader' `;
  
  const freeLeadersSqlite = db.prepare(query).all();
  res.json(freeLeadersSqlite);
});

app.get('/api/freeCompanys', (req, res) => {
  const query = `SELECT company_id, name, user_id FROM companys WHERE user_id IS NULL`;
  
  const freeCompanysSqlite = db.prepare(query).all();
  res.json(freeCompanysSqlite);
});

app.get('/api/freeMembers', (req, res) => {
  const query = `SELECT username, user_id
    FROM users
    WHERE peleton_id IS NULL AND role = 'member'`;
  
    const freeMembersSqlite = db.prepare(query).all();
    res.json(freeMembersSqlite);
});

app.get('/api/currentUser', (req, res) => {
  const query = `SELECT user_id, username, role, email, peleton_id FROM users WHERE username = ? AND role = ? AND email = ?`;
  const statement = db.prepare(query);
  const user = statement.get(req.session.username, req.session.userRole, req.session.userEmail);

  res.json(user);
});

app.get('/api/leaderCurrentAllInfo', (req, res) => {
  const sessionId = req.session.userId;
  const query = `
  SELECT c.company_id, c.name AS company_name, 
  p.peleton_id, p.name AS peleton_name, 
  u.user_id, u.username, u.email
  FROM companys c
  INNER JOIN peletons p ON c.company_id = p.company_id
  INNER JOIN users u ON p.peleton_id = u.peleton_id
  WHERE c.user_id = ?`;

  const statement = db.prepare(query);
  const companyInfo = statement.all(sessionId);
  res.json(companyInfo);
});

app.get('/api/leaderCurrentUserAllPeleton/:id', (req, res) => {
  const companyId = req.params.id;
  const query = `
    SELECT peletons.name, peletons.peleton_id
    FROM peletons
    WHERE peletons.company_id = ?
  `;

  const statement = db.prepare(query);
  const peletonInfo = statement.all(companyId);
  res.json(peletonInfo);
});

app.get('/api/fellowMembers/:id', (req, res) => {
  const peletonId = req.params.id;
  const sessionId = req.session.userId;

  const query = `
    SELECT users.username, users.user_id
    FROM users
    WHERE users.peleton_id = ? AND users.user_id != ?
  `;

  const statement = db.prepare(query);
  const memberInfo = statement.all(peletonId, sessionId);
  res.json(memberInfo);
});

app.get('/api/memberPeletonCompany', (req, res) => {
  const sessionId = req.session.userId;

  const query = `
    SELECT peletons.name AS peleton_name, companys.name AS company_name
    FROM users
    INNER JOIN peletons ON users.peleton_id = peletons.peleton_id
    INNER JOIN companys ON peletons.company_id = companys.company_id
    WHERE users.user_id = ?
  `;

  const statement = db.prepare(query);
  const user = statement.get(sessionId);

  res.json(user);
});

//-----------------------------create, update & delete admin-----------------------------------
app.post('/createCompany', (req, res) => {
  const { companyName, leaderId } = req.body;
  console.log(companyName, leaderId);

  const query = `INSERT INTO companys (name, user_id) VALUES (?, ?);`;
  const statement = db.prepare(query);
  statement.run(companyName, leaderId);

  res.redirect('/main/admin');
});

app.post('/createPeleton', (req, res) => {
  const { peletonName, companyId } = req.body;
  console.log(peletonName, companyId);

  const query = `INSERT INTO peletons (name, company_id) VALUES (?, ?);`;
  const statement = db.prepare(query);
  statement.run(peletonName, companyId);

  res.redirect('/main/admin');
});

app.post('/assignMember', (req, res) => {
  const { memberId, peletonId, source } = req.body;
  console.log(memberId, peletonId);

  const query = `UPDATE users SET peleton_id = ? WHERE user_id = ?;`;
  const statement = db.prepare(query);
  statement.run(peletonId, memberId);

  console.log(source);

  if (source === 'admin') {
    res.redirect('/main/admin');
  } else {
    res.redirect('/main/leader');
  }
});

app.post('/assignLeader', (req, res) => {
  const { leaderId, companyId } = req.body;
  console.log(leaderId, companyId);

  const query = `UPDATE companys SET user_id = ? WHERE company_id = ?;`;
  const statement = db.prepare(query);
  statement.run(leaderId, companyId);

  res.redirect('/main/admin');
});

//-----Delete-----
app.delete('/deleteCompany/:id', (req, res) => {
  const companyId = req.params.id;
  const query = `DELETE FROM companys WHERE company_id = ?`;

  const statement = db.prepare(query);
  statement.run(companyId)

  res.redirect('/main/admin');
});

app.delete('/deletePeleton/:id', (req, res) => {
  const companyId = req.params.id;
  console.log(companyId)
  const query = `DELETE FROM peletons WHERE peleton_id = ?`;

  const statement = db.prepare(query);
  statement.run(companyId)

  res.redirect('/main/admin');
});

app.delete('/deleteUser/:id', (req, res) => {
  const companyId = req.params.id;
  const query = `DELETE FROM users WHERE user_id = ?`;

  const statement = db.prepare(query);
  statement.run(companyId)

  res.redirect('/main/admin');
});

//-----Update-----
app.put('/editCompany', (req, res) => {
  const { companyId, companyName, leaderId, leaderMail } = req.body;

  let query = `UPDATE companys
                SET name = ?, user_id = ?
                WHERE company_id = ?`;

  let statement = db.prepare(query);
  statement.run(companyName, leaderId, companyId);

  query = `UPDATE users
           SET email = ?
           WHERE user_id = ?`;

  statement = db.prepare(query);
  statement.run(leaderMail, leaderId);

  res.redirect('/main/admin');
});

app.put('/editPeleton', (req, res) => {
  const { editPeletonId, editPeletonName } = req.body;

  const query = `UPDATE peletons
                SET name = ?
                WHERE peleton_id = ?`;

  const statement = db.prepare(query);
  statement.run(editPeletonName, editPeletonId);

  res.redirect('/main/admin');
});

app.put('/editMember', (req, res) => {
  const { editMemberId, editMemberPeleton, editMemberMail, editMemberName } = req.body;

  const query = `UPDATE users
                SET peleton_id = ?, email = ?, username = ?
                WHERE user_id = ?`;
  
  const statement = db.prepare(query);
  statement.run(editMemberPeleton, editMemberMail, editMemberName, editMemberId);
  res.redirect('/main/admin');
});

//-----------------------------update & delete leader-----------------------------------
//-----Update-----
app.put('/leaderEditMember', (req, res) => {
  const { memberId, username, email} = req.body;
  
  const query = `UPDATE users SET username = ?, email = ? WHERE user_id = ?`;
  const statement = db.prepare(query);
  statement.run(username, email, memberId);
  res.redirect('/main/leader');
});

app.put('/leaderUnassignMember', (req, res) => {
  const { memberId } = req.body;
  
  const query = `UPDATE users SET peleton_id = NULL WHERE user_id = ?`;
  const statement = db.prepare(query);
  statement.run(memberId);
  res.redirect('/main/leader');
});

//-----Delete-----
app.delete('/leaderDeleteMember', (req, res) => {
  const { memberId } = req.body;
  
  const query = `DELETE FROM users WHERE user_id = ?`;
  const statement = db.prepare(query);
  statement.run(memberId);
  res.redirect('/main/leader');
});


//-----------------------------update & delete member-----------------------------------
//-----Update-----
app.put('/memberEditMember/', (req, res) => {
  const { memberId, username, email } = req.body;

  const query = `UPDATE users SET username = ?, email = ? WHERE user_id = ?`;

  const statement = db.prepare(query);
  statement.run(username, email, memberId);
  res.redirect('/main/member');
});

//-----Delete-----


//------------------------------PORTS----------------------------------

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});

//------------------------------END----------------------------------

