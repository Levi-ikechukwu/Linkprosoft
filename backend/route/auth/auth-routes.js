import express from 'express'
import { authMiddleware, registerUser, loginUser, logoutUser } from '../../controllers/auth/auth-controller.js'


const router = express.Router()

router.get("/check-auth", authMiddleware, (req, res) => {
    const user = req.user
    
    res.status(200).json({
        success: true,
        message: "Authenticated User",
        user,
    })
})


router.post("/register", registerUser)


router.post("/login", loginUser)


router.post("/logout", logoutUser)


export default router