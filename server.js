const express = require("express");
const app = express();
const port = 9000;
const mysql2 = require("mysql2");
const bcrypt = require("bcrypt");
const cors = require("cors");
const session = require("express-session");
const MySQLStore = require("express-mysql-session")(session);

const saltRounds = 10;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors());

const conn = mysql2.createConnection({
  host: "localhost",
  user: "root",
  password: "",
  database: "kmshop_db2",
});

const sessionStore = new MySQLStore(
  {
    expiration: 10800000, // 3 hours
    autoRemove: "interval",
    autoRemoveInterval: 60, // minutes
    clearExpired: true,
    createDatabaseTable: true,
    schema: {
      tableName: "sessions",
      columnNames: {
        session_id: "session_id",
        expires: "expires",
        data: "data",
      },
    },
  },
  conn.promise()
);

app.use(
  session({
    secret: "secret-key",
    store: sessionStore,
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: 10800000, // 3 hours
      httpOnly: true,
      secure: false,
    },
  })
);
app.post("/logout", (req, res) => {
  // ลบ Session ของผู้ใช้งาน
  req.session.destroy((err) => {
    if (err) {
      console.log(err);
      return res.status(500).json({ message: "Internal Server Error" });
    }
    return res.status(200).json({ message: "Logout success" });
  });
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const sql = "SELECT * FROM users WHERE email = ?";
  conn.execute(sql, [email], async (err, results) => {
    if (err) {
      console.log(err);
      return res.status(500).json({ message: "Internal Server Error" });
    }
    if (results.length === 0) {
      return res.status(401).json({ message: "Email or Password incorrect" });
    }
    const user = results[0];
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: "Email or Password incorrect" });
    }
    return res.status(200).json({ message: "Login success", data: user });
  });
});

app.get("/users", async (req, res) => {
  let sql = "SELECT * FROM users";

  await conn.execute(sql, (err, results) => {
    if (err) {
      res.status(500).json({
        message: err.message,
      });
      return;
    }
    res.status(200).json({
      message: "เรียกข้อมูลสำเร็จ",
      data: results,
    });
  });
});

app.post("/register", async (req, res) => {
  const { fname, lname, email, password, address, phone } = req.body;
  let urole = "member";
  bcrypt.genSalt(saltRounds, (err, salt) => {
    bcrypt.hash(password, salt, (err, hash) => {
      let sql =
        "INSERT INTO users (fname,lname,email, password,address,phone,urole) VALUES (?, ?,?,?,?,?,?)";
      conn.execute(
        sql,
        [fname, lname, email, hash, address, phone, urole],
        (err, results) => {
          if (err) {
            res.status(500).json({
              message: err.message,
            });
            return;
          }
          res.status(200).json({
            message: "ส่งข้อมูลสำเร็จ",
            data: results,
          });
        }
      );
    });
  });
});

app.get("/users/:id", async (req, res) => {
  const { id } = req.params;
  let sql = "SELECT * FROM users WHERE id = ?";
  conn.execute(sql, [id], (err, results) => {
    if (err) {
      res.status(500).json({
        message: err.message,
      });
      return;
    }
    res.status(200).json({
      message: "เรียกข้อมูลสำเร็จ",
      data: results,
    });
  });
});

app.put("/users/:id", async (req, res) => {
  const { id } = req.params;
  const { email, password } = req.body;

  bcrypt.genSalt(saltRounds, (err, salt) => {
    bcrypt.hash(password, salt, (err, hash) => {
      let sql = "UPDATE users SET email =? , password = ? WHERE id = ?";
      conn.execute(sql, [email, hash, id], (err, results) => {
        if (err) {
          res.status(500).json({
            message: err.message,
          });
          return;
        }
        res.status(200).json({
          message: "แก้ไขข้อมูลสำเร็จ",
          data: results,
        });
      });
    });
  });
});

app.delete("/users/:id", async (reg, res) => {
  const { id } = reg.params;
  let sql = "DELETE FROM users WHERE  id = ? ";
  await conn.execute(sql, [id], (err, results) => {
    if (err) {
      res.status(500).json({
        message: err.massage,
      });
      return;
    }
    res.status(200).json({
      message: "ลบข้อมูลเรียบร้อย",
      data: results,
    });
  });
});

app.listen(port, () => {
  console.log(`server listening on port ${port}`);
});
