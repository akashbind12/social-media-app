const router = require("express").Router();
const User = require("../models/User");
const bcrypt = require("bcrypt");
const dotenv = require("dotenv");
dotenv.config();
const { body, validationResult } = require("express-validator");
const jwt = require("jsonwebtoken");


// REGISTER
router.post("/register",
body("username")
.not()
.isEmpty()
.withMessage("username can't be empty")
.custom(async (value) => {
  const user = await User.findOne({ username: value });
  if (user) {
    throw new Error("username already exists");
  }
  return true;
}),
body("email")
.not()
.isEmpty()
.withMessage("email can't be empty")
.custom(async (value) => {
  const emailid = await User.findOne({ email: value });
  if (emailid) {
    throw new Error("email already exists");
  }
  return true;
}),
body("password")
.not()
.isEmpty()
.withMessage("password can't be empty"),
async (req, res) => {
  try {

    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    // HASHING THE PASSWORD
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(req.body.password, salt);

    // COLLIECTIONG USER INFORMATION
    const newUser = new User({
      username: req.body.username,
      email: req.body.email,
      password: hashedPassword,
      profilePicture:req.body.profilePicture,
      coveredPicture:req.body.coveredPicture,
      relationships:req.body.relationships,
      city:req.body.city,
      from:req.body.from,
      description:req.body.description,
    });

    // SAVING USER INFORMATION TO DATABASE
    const user = await newUser.save();

    return res.status(200).json(user);
  } catch (error) {
    return res.status(500).json(error);
  }
});


// LOGIN 

router.post("/login",
body("email")
  .not()
  .isEmpty()
  .withMessage("email can't be empty")
  .custom(async (value) => {
    const user = await User.findOne({ email: value });
    if (!user) {
      throw new Error("user does not exists");
    }
    return true;
  }),
body("password").not().isEmpty().withMessage("password can't be empty"),

async (req, res) => {
  try {

    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    //   FINDING USER BY EMAIL IN DB
    const user = await User.findOne({ email: req.body.email });


    // IF USER NOT FOUND IN DB THEN
    if (!user) {
      return !user && res.status(404).json("user not found");
    }

    // COMPARING PASSWORD 
    const validPassword = await bcrypt.compare(
      req.body.password,
      user.password
    );
    
    // IF PASSWORD DOES NOT MATCH THEN
    if (!validPassword) {
      return res.status(400).json("wrong password");
    }

    // GENERATING ACCESS TOKEN
    const accessToken = jwt.sign(
      {
        id: user._id,
        isAdmin: user.isAdmin,
      },
      process.env.JWT_SEC
    );

    const { password, ...others } = user._doc;


    // IF EVERYTHING IS OK THEN
    return res.status(200).json({...others, accessToken });
  } catch (error) {
    return res.status(500).json(error);
  }
});

module.exports = router;
