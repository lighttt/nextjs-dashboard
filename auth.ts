import type { User } from '@/app/lib/definitions';
import { sql } from '@vercel/postgres';
import bcrypt from 'bcrypt';
import NextAuth from 'next-auth';
import credentials from 'next-auth/providers/credentials';
import { z } from 'zod';
import { authConfig } from './auth.config';

async function getUser(email: string): Promise<User | undefined> {
  try {
    const user = await sql<User>`SELECT * FROM users WHERE email=${email}`;
    return user.rows[0];
  } catch (error) {
    console.error('Failed to fetch user:', error);
    throw new Error('Failed to fetch user.');
  }
}

export const { auth, signIn, signOut } = NextAuth({
  ...authConfig,
  providers: [
    credentials({
      async authorize(credentials) {
        const parsedCredentails = z
          .object({
            email: z.string().email(),
            password: z.string().min(6),
          })
          .safeParse(credentials);

        if (parsedCredentails.success) {
          const { email, password } = parsedCredentails.data;
          const user = await getUser(email);
          if (!user) return null;

          const passwordMatch = await bcrypt.compare(password, user.password);
          if (passwordMatch) {
            return user;
          }
        }
        return null;
      },
    }),
  ],
});
