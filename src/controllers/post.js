const router = require("express").Router();
const Post = require("../models/Post");
const User = require("../models/User");

//CREATE A POST

router.post("/", async (req, res) => {
  // COLLECTING INFORMATION OF POST
  const newPost = new Post(req.body);
  try {
    // SAVING TO DATABASE
    const savedPost = await newPost.save();

    return res.status(200).json(savedPost);
  } catch (error) {
    return res.status(500).json(error);
  }
});

// UPDATE POST

router.put("/:id", async (req, res) => {
  try {

    // FINDING POST THAT YOU WANT TO UPDATE
    const post = await Post.findById(req.params.id);


    // MAKING SURE THAT OTHERS COULD NOT UPDATE YOUR POST
    if (post.userId === req.body.userId) {
      await post.updateOne({ $set: req.body });

      return res.status(200).json("post has been updated");
    } else {
      return res.status(403).json("you can update only your post");
    }
  } catch (error) {
    return res.status(500).json(error);
  }
});


// DELETE POST

router.delete("/:id", async (req, res) => {
  try {

    // FINDING POST THAT YOU WANT TO DELETE
    const post = await Post.findById(req.params.id);


     // MAKING SURE THAT OTHERS COULD NOT DELETE YOUR POST
    if (post.userId === req.body.userId) {
      await post.deleteOne();

      return res.status(200).json("post has been deleted");
    } else {
      return res.status(403).json("you can delete only your post");
    }
  } catch (error) {
    return res.status(500).json(error);
  }
});

// LIKES DISLIKE A POST

router.put("/:id/like", async (req, res) => {
  try {

    // FINDING POST THAT YOU WANT TO LIKE/DISLIKE
    const post = await Post.findById(req.params.id);

    // THIS WILL SIMPLY CHECK IF YOU ARE IN OUR DATABASE OR NOT
    const validUser = await User.findById(req.body.userId);
    if(!validUser){
      return res.status(404).json("It seems like you are not authenticated, please login first")
    }


    // IF YOU ALREADY LIKED THIS POST THEN DISLIKE IT OR IF YOU ALREADY DISLIKED OR NOT LIKED THIS POST THEN LIKE IT
    if (!post.likes.includes(req.body.userId)) {

        
        // PUSHING YOUR INFO TO THE POST
      await post.updateOne({ $push: { likes: req.body.userId } });

      return res.status(200).json("post has been liked");
    } else {

        // PULLING YOUR INFO FORM THE POST
      await post.updateOne({ $pull: { likes: req.body.userId } });
      return res.status(200).json("post has been disliked");
    }
  } catch (error) {
    return res.status(500).json(error);
  }
});

// GET A POST

router.get("/:id",async(req,res)=>{

  try {
    const post=await Post.findById(req.params.id)

    return res.status(200).json(post)
  } catch (error) {
    return res.status(500).json(error)
  }
});


// GET  POST of SINGLE USER

router.get("/profile/:username",async(req,res)=>{

  try {
    const user=await User.findOne({username:req.params.username})
    // GETTING ALL POST OF  USER
    const userPosts=await Post.find({userId:user._id});
    
    return res.status(200).json(userPosts)
  } catch (error) {
    return res.status(500).json(error)
  }
})


// GET TIMELIME POSTS

router.get("/timeline/:userId",async(req,res)=>{
  try {

    // GETTING INFO OF USER
    const currentUser=await User.findById(req.params.userId);

    // GETTING ALL POST OF THIS USER
    const userPosts=await Post.find({userId:currentUser._id});


    // GETTING ALL POST OF PEOPLE WHOM I AM FOLLOWING
    const friendPost=await Promise.all(
      currentUser.followings.map((friendId)=>{
        return Post.find({userId:friendId})
      })
    )

    // CONCATENATING MY POST AND POST OF PEOPLE WHOM I AM FOLLOWING
    return res.status(200).json(userPosts.concat(...friendPost))
  } catch (error) {
    return res.status(500).json(error)
  }
})



module.exports = router;
