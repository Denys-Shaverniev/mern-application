const { Router } = require("express")
const User = require("../models/User")
const config = require("config")
const bcrypt = require("bcrypt")
const jwt = require("jsonwebtoken")
const { check, validationResult } = require("express-validator")
const router = Router()

// REGISTER
router.post(
    "/register",
    [
        check("email", "Введите корректный email").isEmail(),
        check("password", "Минимальное количество символов 6")
            .isLength({ min: 6 })
    ],
    async (req, res) => {
        try {
            const errors = validationResult(req)

            if (!errors.isEmpty()) {
                return res.status(400).json({
                    errors: errors.array(),
                    message: "Некорректные данные при регистрации"
                })
            }


            const { email, password } = req.body

            const candidate = await User.findOne({ email })

            if (candidate) {
                return res.status(400).json({ message: "Такой пользователь уже существует" })
            }

            const hashedPassword = await bcrypt.hash(password, 12)
            const user = new User({ email, password: hashedPassword })


            await user.save()

            res.status(201).json({ message: "Пользователь создан" })

        } catch (error) {
            res.status(500).json({ message: "Что-то пошло не так :(" })
        }
    })

// LOGIN
router.post("/login",
    [
        check("email", "Введите корректный email").isEmail(),
        check("password", "Введите корректный пароль").exists()
    ],
    async (req, res) => {
        try {
            const errors = validationResult(req)

            if (!errors.isEmpty()) {
                return res.status(400).json({
                    errors: errors.array(),
                    message: "Некорректные данные при входе в систему"
                })
            }


            const { email, password } = req.body

            const user = await User.findOne({ email })

            if (!user) {
                return res.status(400).json({ message: "Пользователь не найден" })
            }

            const isMatch = await bcrypt.compare(password, user.password)

            if (!isMatch) {
                return res.status(400).json({ message: "Неверный пароль" })
            }

            const token = jwt.sign(
                { userId: user.id },
                config.get("jwtSecret"),
                { expiresIn: "1h" }
            )

            res.json({ token, userId: user.id })

        } catch (error) {
            res.status(500).json({ message: "Что-то пошло не так :(" })
        }
    })

module.exports = router