const express = require("express");
const env = require("dotenv").config();
const cors = require("cors");
const bcrypt = require("bcrypt");
const { pool } = require("./database/connection.js");
const jwt = require("jsonwebtoken");
const app = express();

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on PORT:${PORT}`);
});

app.use(cors());
app.use(express.json());

const key = process.env.SECRET_KEY

const verifyToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return res.status(401).json({ message: "Token no valido 1" });
  }
  const [bearer, token] = authHeader.split(" ");

  if (bearer !== "Bearer" || !token) {
    return res.status(401).json({ message: "Token no valido 2" });
  }
  try {
    jwt.verify(token, key) && next();
  } catch (error) {
    console.log(error);
    return res.status(401).json({ message: "Token no valido 3" });
  }
};

app.post("/usuarios", async (req, res) => {
  try {
    const { email, password, rol, lenguage } = req.body;
    const query = "INSERT INTO usuarios (id, email, rol, lenguage) VALUES (DEFAULT, $1, $2, $3, $4) RETURNING *;";
    const values = [email, bcrypt.hashSync(password), rol, lenguage];
    const { rows } = await pool.query(query, values);
    res.status(201).json({
      id: rows[0].id,
      email: rows[0].email
    });
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Internal server error 1" });
  }
});

app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const query = "SELECT * FROM usuarios WHERE email = $1;";
    const values = [email];
    const { rows } = await pool.query(query, values);

    if (!rows.length) {
      return res.status(404).json({
        message: "Usuario no encontrado 1",
        code: 404,
      });
    }

    const user = rows[0];
    const verifyUser = bcrypt.compareSync(password, user.password);
    if (!verifyUser) {
      return res.status(401).json({
        message: "Credenciales incorrectas 1",
        code: 401,
      });
    }

    const token = jwt.sign(
      {
        email: user.email,
        rol: user.rol,
        lenguage: user.lenguage,
      },
      key
    );

    res.status(200).json({ message: "token", token });
  } catch (error) {
    console.log(error);
    res.status(500).json({ meesage: "Internal server error 2" });
  }
});

app.get("/usuarios", verifyToken, async (req, res) => {
  try {
    const [_, token] = req.headers.authorization.split(" ");
    const query = "SELECT * from usuarios WHERE email = $1;";
    const { email } = jwt.verify(token, key);
    const { rows } = await pool.query(query, [email]);
    const user = rows[0];

    if (!user) {
      return res
        .status(404)
        .json({ message: "Usuario no encontrado 2", code: 404 });
    }
    res.status(200).json(user);
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Internal server error 3" });
  }
});
