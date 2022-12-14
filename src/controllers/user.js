const router=require('express').Router()
const bcrypt=require("bcrypt")
const User = require('../models/User')
const {verifyToken, verifyTokenAndAuthorization,verifyTokenAndAdmin}=require("../middlewares/verifyToken")
const { body, validationResult } = require('express-validator');


// UDATING USER

router.put("/:id", async(req,res)=>{
 
        if(req.body.userId===req.params.id || req.body.isAdmin){


            // IF USER TRY TO UPDATE PASSWORD THEN HASH IT FIRST
            if(req.body.password){
                try {
                    
                    // HASHING PASSWORD
                    const salt=await bcrypt.genSalt(10)
                    req.body.password=await bcrypt.hash(req.body.password,salt);
                  
                } catch (error) {
                    return res.status(500).json(error)
                }
            }

            // SAVING UPDATED USER TO DATABASE
            try {
                const user=await User.findByIdAndUpdate(req.body.userId,{$set:req.body},{new:true})
                return res.status(200).json(user)
            } catch (error) {
                return res.status(500).json(error)
            }
        }else{
            return res.status(403).json("You can update only your account.")
        }
   
});



// DELETING USER

router.delete("/:id",verifyTokenAndAuthorization,
body("userId").not().isEmpty().withMessage("Please provide your userId"),
async(req,res)=>{

    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    
    // CHECKING WHETHER THE CURRENT USER IS TRYING TO DELETE HIS/HER OWN ACCOUNT OR NOT
    if(req.body.userId===req.params.id || req.body.isAdmin){


    
        // DELETING USER FROM DATABASE
        try {
            await User.findByIdAndDelete(req.body.userId)
            return res.status(200).json("Account has been deleted")
        } catch (error) {
            return res.status(500).json(err)
        }
    }else{
        return res.status(403).json("You can delete only your account.")
    }

});

// GET ALL  USER
router.get("/all",async(req,res)=>{

   try {
       const user =await User.find()
       return res.status(200).json(user);
   } catch (error) {
       return res.status(500).json(error);
   }
});



// GET USER
router.get("/",async(req,res)=>{
    const username = req.query.username;
    const userId=req.query.userId;
   try {
       const user =username? await User.findOne({username:username}) :await User.findOne({_id:userId})

      //  DESTRUCTURNING USER SO THAT I COULD NOT SEND SENSATIVE INFORMATION LIKE PASSWORD OR SOMETING ELSE
       const {password,...other}=user._doc;


    //    SENDING INFORMATING OTHER THAN PASSWORD
       return res.status(200).json(other);
   } catch (error) {
       return res.status(500).json(error);
   }
    

});



// FOLLOW A USER

router.put("/:id/follow",verifyToken,
body("userId").not().isEmpty().withMessage("Please provide your userId"),
async(req,res)=>{
 

    // MAKING SURE THAT USER COULD NOT FOLLOW HIS SELF/ HER SELF
    if(req.body.userId !== req.params.id){

        try {

            const errors = validationResult(req);
            if (!errors.isEmpty()) {
              return res.status(400).json({ errors: errors.array() });
            }
            // FINDING USER INFORMATION THAT YOU WANT TO FOLLOW
            const user= await User.findById(req.params.id);

            // FINDING YOUR INFORMATION
            const currentUser = await User.findById(req.body.userId);


            // CHECKING WHETHER YOU ALREADY FOLLOW HIM OR NOT
            if(!user.followers.includes(req.body.userId)){

                // PUSHING YOUR INFO TO THE USER YOU ARE GOING TO FOLLOW
                await user.updateOne({$push:{followers:req.body.userId}})

                // PUSHING INFO TO YOUR ACCOUNT  OF  THAT USER THAT YOU ARE GOING TO FOLLOW
                await currentUser.updateOne({$push:{followings:req.params.id}})

                return res.status(200).json("user has been followed")
            }else{
                return res.status(403).json("you already follow this user")
            }
            
        } catch (error) {
            return res.status(500).json(error)
        }
        

    }else{
        return res.status(403).json("You cannot follow yourself.")
    }

});


// UNFOLLOW A USER
router.put("/:id/unfollow",verifyToken,
body("userId").not().isEmpty().withMessage("Please, provide your userid"),
async(req,res)=>{
 

    // MAKING SURE THAT YOU ARE GOING NOT TO UNFOLLOW YOURSELF
    if(req.body.userId !== req.params.id){

        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
              return res.status(400).json({ errors: errors.array() });
            }

            // FINDING USER INFORMATION THAT YOU WANT TO UNFOLLOW
            const user= await User.findById(req.params.id);

            // FINDING YOUR INFORMATION
            const currentUser = await User.findById(req.body.userId);


            // CHECKING WHETHER YOU ALREADY FOLLOW HIM OR NOT
            if(user.followers.includes(req.body.userId)){

                // PULLING YOUR INFO FROM THE USER YOU ARE GOING TO UNFOLLOW
                await user.updateOne({$pull:{followers:req.body.userId}})

                // PULLING INFO FROM YOUR ACCOUNT  OF  THAT USER THAT YOU ARE GOING TO UNFOLLOW
                await currentUser.updateOne({$pull:{followings:req.params.id}})

                return res.status(200).json("user has been unfollowed")
            }else{
                return res.status(403).json("you don't follow this user")
            }
            
        } catch (error) {
            return res.status(500).json(error)
        }
        

    }else{
        return res.status(403).json("You cannot unfollow yourself.")
    }

});


module.exports =router;