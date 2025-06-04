import type { Request, Response } from "express";
import User from "../models/User";
import { checkPassword, hashPassword } from "../utils/auth";
import Token from "../models/Token";
import { generateToken } from "../utils/token";
import { AuthEmail } from "../emails/AuthEmail";
import { generateJWT } from "../utils/jwt";

export class AuthController {
    static createAccount = async (req: Request, res: Response) => {
        try {
            const { password, email } = req.body

            //Prevent users duplication
            const userExists = await User.findOne({ email })
            if (userExists) {
                const error = new Error('Este usuario ya existe')
                res.status(409).json({ error: error.message })
                return
            }
            // Create a new user
            const user = new User(req.body)

            // Hash Password
            user.password = await hashPassword(password)

            // Generate Token
            const token = new Token()
            token.token = generateToken()
            token.user = user.id

            // Send email
            AuthEmail.sendConfirmationEmail({
                email: user.email,
                name: user.name,
                token: token.token
            })

            await Promise.allSettled([user.save(), token.save()])

            res.send('¡Cuenta creada! Revisa tu correo para confirmarla')

        } catch (error) {
            res.status(500).json({ error: 'Hubo un error' })
        }
    }

    static confirmAccount = async (req: Request, res: Response) => {
        try {
            const { token } = req.body

            const tokenExists = await Token.findOne({ token })
            if (!tokenExists) {
                const error = new Error('Código de confirmación no válido')
                res.status(404).json({ error: error.message })
            }

            const user = await User.findById(tokenExists.user)
            user.confirmed = true

            await Promise.allSettled([user.save(), tokenExists.deleteOne()])
            res.send('Tu cuenta ha sido confirmada')

        } catch (error) {
            res.status(500).json({ error: 'Hubo un error' })
        }
    }

    static login = async (req: Request, res: Response) => {
        try {
            const { email, password } = req.body
            const user = await User.findOne({ email })

            if (!user) {
                const error = new Error('Usuario no encontrado')
                res.status(404).json({ error: error.message })
            }

            if (!user.confirmed) {
                const token = new Token()
                token.user = user.id
                token.token = generateToken()
                await token.save()

                // Send email
                AuthEmail.sendConfirmationEmail({
                    email: user.email,
                    name: user.name,
                    token: token.token
                })

                const error = new Error('Esta cuenta no ha sido confirmada, te hemos enviado un correo de confirmación')
                res.status(401).json({ error: error.message })
            }

            // Check Password
            const isPasswordCorrect = await checkPassword(password, user.password)
            if (!isPasswordCorrect) {
                const error = new Error('Contraseña incorrecta')
                res.status(401).json({ error: error.message })
                return
            }

            const token = generateJWT({ id: user.id })

            res.send(token)

        } catch (error) {
            res.status(500).json({ error: 'Hubo un error' })
        }
    }

    static requestConfirmationCode = async (req: Request, res: Response) => {
        try {
            const { email } = req.body

            // User exists
            const user = await User.findOne({ email })
            if (!user) {
                const error = new Error('Este usuario no existe')
                res.status(404).json({ error: error.message })
                return
            }

            if (user.confirmed) {
                const error = new Error('Este usuario ya está confirmado')
                res.status(403).json({ error: error.message })
                return
            }

            // Generate Token
            const token = new Token()
            token.token = generateToken()
            token.user = user.id

            // Send email
            AuthEmail.sendConfirmationEmail({
                email: user.email,
                name: user.name,
                token: token.token
            })

            await Promise.allSettled([user.save(), token.save()])

            res.send('Hemos enviado un nuevo código a tu correo')

        } catch (error) {
            res.status(500).json({ error: 'Hubo un error' })
        }
    }

    static forgotPassword = async (req: Request, res: Response) => {
        try {
            const { email } = req.body

            // User exists
            const user = await User.findOne({ email })
            if (!user) {
                const error = new Error('Este usuario no existe')
                res.status(404).json({ error: error.message })
                return
            }

            // Generate Token
            const token = new Token()
            token.token = generateToken()
            token.user = user.id
            await token.save()

            // Send email
            AuthEmail.sendPasswordResetToken({
                email: user.email,
                name: user.name,
                token: token.token
            })

            res.send('En tu correo tendrás instrucciones para reestablecer tu contraseña')

        } catch (error) {
            res.status(500).json({ error: 'Hubo un error' })
        }
    }

    static validateToken = async (req: Request, res: Response) => {
        try {
            const { token } = req.body

            const tokenExists = await Token.findOne({ token })
            if (!tokenExists) {
                const error = new Error('Código de confirmación no válido')
                res.status(404).json({ error: error.message })
                return
            }

            res.send('Código válido, define tu nueva contraseña')

        } catch (error) {
            res.status(500).json({ error: 'Hubo un error' })
        }
    }

    static updatePasswordWithToken = async (req: Request, res: Response) => {
        try {
            const { token } = req.params
            const { password } = req.body

            const tokenExists = await Token.findOne({ token })
            if (!tokenExists) {
                const error = new Error('Código de confirmación no válido')
                res.status(404).json({ error: error.message })
                return
            }

            const user = await User.findById(tokenExists.user)
            user.password = await hashPassword(password)

            await Promise.allSettled([user.save(), tokenExists.deleteOne()])

            res.send('Tu contraseña ha sido reestablecida correctamente')

        } catch (error) {
            res.status(500).json({ error: 'Hubo un error' })
        }
    }

    static user = async (req: Request, res: Response) => {
        res.json(req.user)
        return
    }

    static updateProfile = async (req: Request, res: Response) => {
        const { name, email } = req.body

        const userExists = await User.findOne({ email })
        if (userExists && userExists.id.toString() !== req.user.id.toString()) {
            const error = new Error('Este correo ya está registrado')
            res.status(409).json({ error: error.message })
            return
        }

        req.user.name = name
        req.user.email = email

        try {
            await req.user.save()
            res.send('Perfil actualizado')

        } catch (error) {
            res.status(500).send('Hubo un error')
        }
    }

    static updateCurrentUserPassword = async (req: Request, res: Response) => {
        const { current_password, password } = req.body

        const user = await User.findById(req.user.id)

        const isPasswordCorrect = await checkPassword(current_password, user.password)
        if (!isPasswordCorrect) {
            const error = new Error('La contraseña actual es incorrecta')
            res.status(401).json({ error: error.message })
            return
        }

        try {
            user.password = await hashPassword(password)

            await user.save()
            res.send('Contraseña actualizada')

        } catch (error) {
            res.status(500).send('Hubo un error')
        }
    }

    static checkPassword = async (req: Request, res: Response) => {
        const { password } = req.body

        const user = await User.findById(req.user.id)

        const isPasswordCorrect = await checkPassword(password, user.password)
        if (!isPasswordCorrect) {
            const error = new Error('La contraseña es incorrecta')
            res.status(401).json({ error: error.message })
            return
        }

        res.send('Contraseña correcta')
    }
}