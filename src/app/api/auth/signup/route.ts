import { NextResponse } from 'next/server';
import dbConnect, { DatabaseConnectionError } from '@/lib/db';
import User from '@/models/User';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { cookies } from 'next/headers';

const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-key';

export async function POST(request: Request) {
    try {
        await dbConnect();
        const { email, password, name } = await request.json();

        if (!email || !password) {
            return NextResponse.json({ error: 'Email and password are required' }, { status: 400 });
        }

        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return NextResponse.json({ error: 'User already exists' }, { status: 400 });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const user = await User.create({
            email,
            password: hashedPassword,
            name,
        });

        const token = jwt.sign({ userId: user._id, email: user.email }, JWT_SECRET, {
            expiresIn: '7d',
        });

        // Set HTTP-only cookie
        const cookieStore = await cookies();
        cookieStore.set('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            maxAge: 60 * 60 * 24 * 7, // 7 days
            path: '/',
        });

        return NextResponse.json({
            message: 'User created successfully',
            user: {
                id: user._id,
                email: user.email,
                name: user.name,
            },
        });
    } catch (error: unknown) {
        console.error('Signup error:', error);

        if (error instanceof DatabaseConnectionError) {
            if (error.code === 'DB_AUTH_FAILED') {
                return NextResponse.json(
                    { error: 'Database authentication failed. Please verify MongoDB credentials.' },
                    { status: 503 }
                );
            }

            return NextResponse.json(
                { error: 'Database connection failed. Please try again shortly.' },
                { status: 503 }
            );
        }

        return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
    }
}
