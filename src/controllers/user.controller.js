import {asyncHandler} from '../utils/asyncHandler.js';
import {ApiError} from '../utils/ApiError.js';
import {User} from '../models/user.model.js';
import {uploadOnCloudinary} from '../utils/cloudinary.js';
import {ApiResponse} from '../utils/ApiResponse.js';
import jwt, { decode } from 'jsonwebtoken';
import multer from 'multer';

const genrateAccessAndRefreshTokens =async(userId)=>{
    try{
        const user = await User.findById(userId);
        const accessToken= user.genrateAccessToken();
        const refreshToken= user.genrateRefreshToken();

        user.refreshToken = refreshToken;
        await user.save({validateBeforeSave:false});

        return {accessToken,refreshToken};
    }catch(error){
        throw new ApiError(500,"Something went wrong while genrating Access and Refresh tokens");
    }
}


const registerUser = asyncHandler(async(req,res) => {
    //get user details from frontend
    //validation - not empty
    //check if user already exists - username, email
    //check for images , check for avatar
    //upload images to cloudinary,avatar
    //create user object - create entry in db
    //remove pass and refresh token field from response
    //check for user creation
    //return response


    
    const {fullName,email,username,password}= req.body
    // console.log("email: "+ email);

    if(
        [fullName,email,username,password].some((field) => field?.trim() === "")
    ){
        throw new ApiError(400,"Please fill in all fields");
    }

    const existedUser = await User.findOne({
        $or: [{email},{username}]
    })
    if(existedUser){
        throw new ApiError(409,"User with this email or username already exists");
    }
    // console.log(req.files);

    const avatarLocalPath = req.files?.avatar[0]?.path;
    // const coverImageLocalPath = req.files?.coverImage[0]?.path;
    let coverImageLocalPath;
    if(req.files && Array.isArray(req.files.coverImage) && req.files.coverImage.length > 0){
        coverImageLocalPath = req.files.coverImage[0].path;

    }

    if(!avatarLocalPath){
        throw new ApiError(400,"Please upload avatar image");
    }

    const avatar =await uploadOnCloudinary(avatarLocalPath);
    const coverImage =await uploadOnCloudinary(coverImageLocalPath);
    if(!avatar){
        throw new ApiError(400,"Please upload avatar image");
    }

    const user = await User.create({
        fullName,
        avatar:avatar.url,
        coverImage:coverImage?.url || "",
        email,
        username:username.toLowerCase(),
        password
    })
    const createdUser = await User.findById(user._id).select("-password -refreshToken");


    if(!createdUser){
        throw new ApiError(500,"User creation failed");
    }



    return res.status(201).json(
        new ApiResponse(200, createdUser, "User registered successfully.")
    )

});


const loginUser = asyncHandler(async(req,res) => {
    //req body->body
    //check username or email
    //find user
    //check password
    //access and refresh token will be sent to user
    //send cookies
    //return response

    const {username,email,password} = req.body;

    if(!username && !email){
        throw new ApiError(400,"Please provide username or email");
    }

    const user = await User.findOne({
        $or: [{username},{email}]
    })
    if(!user){
        throw new ApiError(404,"User not found");
    }

    const isPasswordVaild = await user.comparePassword(password);
    if(!isPasswordVaild){
        throw new ApiError(401,"Invalid credentials");
    }
    
    const {accessToken,refreshToken}= await genrateAccessAndRefreshTokens(user._id);

    const loggedInUser = User.findById(user._id).select("-password -refreshToken");

    const options={
        httpOnly:true,
        secure:true
    }

    return res.status(200)
    .cookie("accessToken",accessToken,options)
    .cookie("refreshToken",refreshToken,options)
    .json(
        new ApiResponse(200,{
            user:loggedInUser,
            accessToken,
            refreshToken
        },"User logged in successfully")
    )
});


const logoutUser = asyncHandler(async(req,res) => {
    //clear cookies
    await User.findByIdAndUpdate(req.user._id,{
        $unset:{refreshToken: 1}  //this removes the field from the document
    },
    {
        new:true
    });

    const options={
        httpOnly:true,
        secure:true
    }

    return response.status(200)
    .clearCookie("accessToken",options)
    .clearCookie("refreshToken",options)
    .json(
        new ApiResponse(200,{},"User logged out successfully")
    )
});


const refreshAccessToken = asyncHandler(async(req,res) => {
    //get refresh token from cookie
    //check if refresh token is valid
    //genrate new access token
    //send new access token
    //return response

    const incomingRefreshToken = req.cookies.refreshToken || req.body.refreshToken;
    if (!incomingRefreshToken) {
        throw new ApiError(401, "Unauthorized request");
    }

    try {
        const decodedToken = jwt.verify(
            incomingRefreshToken,
            process.env.REFRESH_TOKEN_SECRET,        
        )
    
        const user =await User.findById(decodedToken?._id)
        if(!user){
            throw new ApiError(401,"Invalid token");
        }
    
        if(user.refreshToken !== incomingRefreshToken){
            throw new ApiError(401,"Refresh token is expired or used");
        }
    
        const options={
            httpOnly : true,
            secure : true,
        }
    
        const {accessToken,newRefreshToken} = await genrateAccessAndRefreshTokens(user._id);
    
        return res.status(200)
        .cookie("accessToken",accessToken,options)
        .cookie("refreshToken",newRefreshToken,options)
        .json(
            new ApiResponse(200,{
                accessToken,
                refreshToken: newRefreshToken
            },"Access token refreshed successfully")
        )
    } catch (error) {
        throw new ApiError(401,error?.message || "Invalid refresh token");
    }
});


const changeCurrentPassword = asyncHandler(async(req,res) => {
    //get old password and new password
    //check current password
    //update password
    //return response

    const {oldPassword,newPassword} = req.body; //{oldPassword,newPassword,confPassword}

    // if(!(confPassword == newPassword)){

    // }
    const user = await User.findById(req.user?._id);
    const isPasswordCorrect = await user.comparePassword(oldPassword);

    if (!isPasswordCorrect) {
        throw new ApiError(400,"Invalid password");
    }

    user.password = newPassword;
    user.save({validateBeforeSave:false});

    return res.status(200)
    .json(
        new ApiResponse(200,{},"Password changed successfully")
    )
}); 


const getCurrentUser = asyncHandler(async(req,res) => {
    //get user from req object
    //return response

    return res.status(200)
    .json(
        new ApiResponse(200,req.user,"User details fetched successfully")
    )
});


const updateAccountDetails = asyncHandler(async(req,res) => {
    //get user from req object
    //update user
    //return response

    const {fullName,email} = req.body;

    if (!fullName && !email) {
        throw new ApiError(400,"Please provide fields to update");
    }

    const user = await User.findByIdAndUpdate(
        req.user._id,
        {
            $set:{
                fullName,
                email: email
            }
        },
        {new:true}
    ).select("-password");

    return res.status(200)
    .json(
        new ApiResponse(200,user,"User details updated successfully")
    )
});


const updateUserAvatar = asyncHandler(async(req,res) => {
    //get user from req object
    //upload avatar
    //update user
    //return response

    const avatarLocalPath = req.file?.path

    if (!avatarLocalPath) {
        throw new ApiError(400,"Please upload avatar image");
    }

    const avatar = await uploadOnCloudinary(avatarLocalPath);

    if (!avatar.url) {
        throw new ApiError(400,"Error while uploading avatar image");
    }

    const user = await User.findByIdAndUpdate(
        req.user?._id,
        {
            $set:{
                avatar: avatar.url
            }
        },
        {new:true}
    ).select("-password");

    return res.status(200)
    .json(
        new ApiResponse(200,user,"Avatar updated successfully")
    )
});


const updateUserCoverImage = asyncHandler(async(req,res) => {
    //get user from req object
    //upload cover image
    //update user
    //return response

    const coverImageLocalPath = req.file?.path

    if (!coverImageLocalPath) {
        throw new ApiError(400,"Please upload cover image");
    }

    const coverImage = await uploadOnCloudinary(coverImageLocalPath);

    if (!coverImage.url) {
        throw new ApiError(400,"Error while uploading cover image");
    }

    const user = await User.findByIdAndUpdate(
        req.user?._id,
        {
            $set:{
                coverImage: coverImage.url
            }
        },
        {new:true}
    ).select("-password");

    return res.status(200)
    .json(
        new ApiResponse(200,user,"Cover image updated successfully")
    )
});


const getUserChannelProfile =  asyncHandler(async(req,res)=>{
    const {username} = req.params;

    if (!username?.trim()) {
        throw new ApiError(400,"Username is missing")
    }

    const channel = await User.aggregate([
        {
            $match:{
                username: username?.toLowerCase()
            }
        },
        {
            $lookup:{
                from: "subscriptions",
                localField: "_id",
                foreignField: "channel",
                as: "subscribers"
            }
        },
        {
            $lookup:{
                from: "subscriptions",
                localField: "_id",
                foreignField: "subscriber",
                as: "subscribedTo"
            }
        },
        {
            $addFields:{
                subscribersCount:{
                    $size: "$subscribers"
                },
                channelsSubscribedToCount:{
                    $size: "$subscribedTo"
                },
                isSubscribed:{
                    $cond:{
                        if:{$in: [req.user?._id, "subscribers.subscriber"]},
                        then: true,
                        else: false
                    }
                }
            }
        },
        {
            $project:{
                fullName: 1,
                username: 1,
                subscribersCount: 1,
                channelsSubscribedToCount: 1,
                isSubscribed: 1,
                avatar : 1 ,
                coverImage: 1,
                email : 1
            }
        }
    ])

    if (!channel?.length) {
        throw new ApiError(404,"Channel does not exists")
    }

    return res.status(200)
    .josn(
        new ApiResponse(200, channel[0],"User channel fetched successfully")
    )
});


const getWatchHistory = asyncHandler(async(req,res)=>{
    const user = await User.aggregate([
        {
            $match:{
                _id: new mongoose.Types.ObjectId(req.user._id)
            }
        },
        {
            $lookup:{
                from : "videos",
                localField: "watchHistory",
                foreignField: "_id",
                as: "watchHistory",
                pipeline:[
                    {
                        $lookup:{
                            from: "users",
                            localField: "owner",
                            foreignField: "_id",
                            as: "owner",
                            pipeline:[
                                    {
                                        $project:{
                                            fullName:1,
                                            username:1,
                                            avatar:1
                                        }
                                    }
                            ]
                        }
                    },
                    {
                        $addFields:{
                            owner:{
                                $first: "$owner"
                            }
                        }
                    }
                ]
            }
        }
    ]);

    return res.status(200)
    .json(
        new ApiResponse(200,user[0].watchHistory, "Watch History fetched successfully")
    )
});

export {
    registerUser , 
    loginUser, 
    logoutUser,
    refreshAccessToken,
    changeCurrentPassword,
    getCurrentUser,
    updateAccountDetails,
    updateUserAvatar,
    updateUserCoverImage,
    getUserChannelProfile,
    getWatchHistory
};