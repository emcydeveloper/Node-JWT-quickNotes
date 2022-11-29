require("dotenv/config");
const express = require("express");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const { verify } = require("jsonwebtoken");
const { hash, compare } = require("bcryptjs");
const { fakeDB } = require("./fakeDB.js");
const { createAccessToken,createRefreshToken,sendAccessToken,sendRefreshToken } = require("./token.js");
const {isAuth} = require('./isAuth.js')

const server = express();
server.use(cookieParser()); //Use a express middleware for easier cookie handling
//Needed to be able to read boby data
server.use(express.json()); //to support JSON-encoded bodies
server.use(express.urlencoded({ extended: true })); //support URL-encoded bodies
server.use(
  cors({
    origin: "http://localhost:4000",
    credentials: true,
  })
);

//Register a user
//Login a user
//Logout a user
//Setup a protected route
//Get a new accesstoken with a refresh token

//Register a user

server.get("/", function (req, res) {
  res.send("Hello World");
});

//Register a user
server.post('/register', async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = fakeDB.find((user) => user.email === email);
    //Check is user exist
    if (user) throw new Error("User already exist");
    //If not user exist, hash passowrd
    const hashedPassword = await hash(password, 10);
    //Insert the user in fake DB
    fakeDB.push({
      id: fakeDB.length,
      email,
      hashedPassword,
    });
    res.send({ message: "User Created" });
    console.log("DB ", fakeDB);
  } catch (err) {
    res.send({ error: `${err.message}` });
    // console.log("Error:", err);
  }
});

//Login a user
server.post('/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    //find user
    const user = fakeDB.find((user) => user.email === email);
    console.log('valid user')
    if (!user) throw new Error("Invalid user");
    //conpare the password with db
    const valid = await compare(password, user.hashedPassword);
    console.log('valid pass')
    if (!valid) throw new Error("Invalid password");
    //Create token
    const accesstoken = createAccessToken(user.id);
    const refreshToken = createRefreshToken(user.id);
    //Add refresh token in fake DB
    user.refreshToken = refreshToken;
    console.log(fakeDB);
    //send Refresh token as a cookie and access token as a regular response
    sendRefreshToken(res,refreshToken);
    sendAccessToken(res,req,accesstoken);
  } catch (err) {
    res.send({ error: `${err.message}` });
  }
});

//Logout a user
server.post('/logout',async (_req,res)=>{
  res.clearCookie('refreshToken',{path:'/refresh_token'});
  return res.send({
    message:'Logged out'
  })
})

//Protected route
server.post('/protected',async(req,res)=>{
  try{
    const userId = isAuth(req);
    if(userId !== null){
      res.send({data:'This is protected data.'})
    }
  }catch(err){
    res.send({ error: `${err.message}` });
  }
})

//Get a new access token with a refresh token
server.post('/refresh_token',async(req,res)=>{
  const token = req.cookies.refreshToken;
  //if we dont have a token in our request
  if(!token) return res.send({accesstoken:''})
  let payload = null;
  try{
    payload = verify(token,process.env.REFRESH_TOKEN_SECRET)
  }catch(err){
    return res.send({accesstoken:''})
  }
  //Token is valid, check if user exist
  const user = fakeDB.find(user => user.id === payload.userId);
  if(!user)return res.send({accesstoken:' '})
  //User exist, check is refreshtoken exist on user
  if(user.refreshToken !== token){
    return res.send({accesstoken:''})
  }
  // Token exist, create new refresh token and access token
  const accesstoken = createAccessToken(user.id);
  const refreshtoken = createRefreshToken(user.id);
  user.refreshToken = refreshtoken;
  // send refresh token and access token
  sendRefreshToken(res,refreshtoken);
  return res.send({accesstoken})

})

server.listen(process.env.PORT, () =>
  console.log(`Server started at port ${process.env.PORT}`)
);