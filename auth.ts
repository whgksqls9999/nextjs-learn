import NextAuth from 'next-auth';
import { authConfig } from './auth.config';
import Credentials from 'next-auth/providers/credentials';
import { z } from 'zod';
import { sql } from '@vercel/postgres';
import type { User } from '@/app/lib/definitions';
import bcrypt from 'bcrypt';


async function getUser(email: string): Promise<User | undefined>{
    try {
        const user = await sql<User> `SELECT * FROM users WHERE email=${email}`;
        return user.rows[0];
    } catch (err) {
        console.error('Failed to fetch user:', err);
        throw new Error('Failed to fetch user.');
    }
}

export const { auth, signIn, signOut } = NextAuth({
    ...authConfig,
    providers: [Credentials({
        async authorize(credentials) {
            // 입력값 유효성 검사
            const parsedCredentials = z
                .object({ email: z.string().email(), password: z.string().min(6) })
                .safeParse(credentials);
            
            if (parsedCredentials.success) {
                // 유저 정보 찾기
                const { email, password } = parsedCredentials.data;
                const user = await getUser(email);
                if (!user) return null;

                // 패스워드 체크
                const passwordsMatch = await bcrypt.compare(password, user.password);

                if (passwordsMatch) return user;
            }

            console.log('Invalid credentials');
            return null;
        }
    })],
});