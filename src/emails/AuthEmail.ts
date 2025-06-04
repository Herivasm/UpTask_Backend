import { transporter } from "../config/nodeMailer"

interface IEmail {
    email: string
    name: string
    token: string
}

export class AuthEmail {
    static sendConfirmationEmail = async (user: IEmail) => {
        const info = await transporter.sendMail({
            from: 'UpTask <admin@uptask.com>',
            to: user.email,
            subject: 'UpTask - Confirmación de correo',
            text: 'UpTask - Confirma tu correo',
            html: `<p>Hola, ${user.name}, tu cuenta en UpTask ha sido creada, solo debes confirmar tu cuenta
                    <p>Visita el siguiente enlace:</p>
                    <a href="${process.env.FRONTEND_URL}/auth/confirm-account">Confirmar cuenta</a>
                    <p>E ingresa el código: <b>${user.token}</b><p/>
                    <p>Tu código expira en 10 minutos</p>
            </p>`
        })
        console.log('Mensaje enviado', info.messageId);
    }

     static sendPasswordResetToken = async (user: IEmail) => {
        const info = await transporter.sendMail({
            from: 'UpTask <admin@uptask.com>',
            to: user.email,
            subject: 'UpTask - Reestablecer Contraseña',
            text: 'UpTask - Reestablece tu contraseña',
            html: `<p>Hola, ${user.name}, has solicitado cambiar tu contraseña.
                    <p>Visita el siguiente enlace:</p>
                    <a href="${process.env.FRONTEND_URL}/auth/new-password">Reestablecer Contraseña</a>
                    <p>E ingresa el código: <b>${user.token}</b><p/>
                    <p>Tu código expira en 10 minutos</p>
            </p>`
        })
        console.log('Mensaje enviado', info.messageId);

    }
}