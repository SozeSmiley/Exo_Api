require("dotenv").config();
const express = require("express");
const app = express();

app.use(express.json());

const fs = require("fs");

const jwt = require('jsonwebtoken');
const secret = process.env.JWT_SECRET;

function jwtMiddleware(req, res, next) {
    const auth = req.headers.authorization
    if (!auth || !auth.startsWith("Bearer ")){
        res.status(401).json({ error : "Authorisation non spécifié." });
        return
    };
    
    const token = auth.split(" ")[1];
    try {
        const decoded = jwt.verify(token, secret);
        req.user = decoded;
    } catch (err) {
        console.error("Token incorrect ou expiré :", err);
        res.status(403).json({ error : "Token incorrect ou expiré."})
        return
    };
    next()
};

const users = [{
    id : 0, 
    username : "adminLogin", 
    password : "adminPass", 
    firstName : "Mike", 
    lastName : "Zalat", 
    role : "ADMIN"
}, {
    id : 1, 
    username : "Login", 
    password : "Pass", 
    firstName : "Second", 
    lastName : "Name", 
    role : "USER"
}];

app.get("/info", (req, res) => {
    fs.readFile("package.json", "utf8", (err, data) => {
        if (err) {
            console.error("Erreur de lecture du fichier :", err);
            res.status(500).json({ error : "Erreur de lecture du fichier." })
            return;
        };
        
        const text = JSON.parse(data).name;
        res.json({ name : text });
    });
});

app.post("/auth", (req, res) => {
    if  (!req.body.username || !req.body.password) {
        res.status(400).json({ error : "Identifiant ou mot de passe non spécifié(s)." });
        return
    };
    const user = users.find(user => user.username === req.body.username 
    && user.password === req.body.password);
    if (!user){
        res.status(401).json({ error : "Identifiant ou mot de passe incorrect(s)." });
        return
    };

    const userInfo = {
        id : user.id, 
        firstName : user.firstName, 
        lastName : user.lastName, 
        role : user.role
    };
    const token = jwt.sign(userInfo, secret, { expiresIn : "1h" });
    res.json({ token : token });
});

app.get("/whoami", jwtMiddleware, (req, res) => {
    res.json({ 
        id  : req.user.id,
        firstName : req.user.firstName, 
        lastName : req.user.lastName, 
        role : req.user.role
    });
});

app.patch("/rename", jwtMiddleware, (req, res) => {
    if (req.user.role !== "ADMIN") {
        res.status(403).json({ error : "Authorisation refusé."})
        return
    };

    const user = users.find(user => user.id === req.body.id);
    if (!user){
        res.status(404).json({ error : "Utilisateur inexistant."})
        return
    }

    user.firstName = req.body.firstName !== undefined ? req.body.firstName : user.firstName;
    user.lastName = req.body.lastName !== undefined ? req.body.lastName : user.lastName;

    res.json(user);
});

app.listen(3000);