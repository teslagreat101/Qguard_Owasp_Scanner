"use client";

import Link from "next/link";
import { Shield, Scan, LayoutDashboard, User, LogOut, Menu } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Sheet, SheetContent, SheetTrigger } from "@/components/ui/sheet";
import { useState } from "react";

export default function Navbar() {
  const [isLoggedIn, setIsLoggedIn] = useState(false);

  return (
    <header className="sticky top-0 z-50 w-full border-b bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
      <div className="container flex h-14 items-center justify-between">
        <div className="flex items-center gap-2">
          <Link href="/" className="flex items-center gap-2 font-bold text-xl">
            <Shield className="h-6 w-6 text-primary" />
            <span>SecretScanner</span>
          </Link>
          <nav className="hidden md:flex items-center gap-6 ml-6">
            <Link
              href="/"
              className="text-sm font-medium text-muted-foreground transition-colors hover:text-primary"
            >
              <Scan className="inline h-4 w-4 mr-1" />
              Scan
            </Link>
            <Link
              href="/dashboard"
              className="text-sm font-medium text-muted-foreground transition-colors hover:text-primary"
            >
              <LayoutDashboard className="inline h-4 w-4 mr-1" />
              Dashboard
            </Link>
          </nav>
        </div>

        <div className="flex items-center gap-2">
          <Sheet>
            <SheetTrigger asChild className="md:hidden">
              <Button variant="ghost" size="icon">
                <Menu className="h-5 w-5" />
              </Button>
            </SheetTrigger>
            <SheetContent side="right">
              <nav className="flex flex-col gap-4 mt-6">
                <Link
                  href="/"
                  className="text-sm font-medium transition-colors hover:text-primary"
                >
                  Scan
                </Link>
                <Link
                  href="/dashboard"
                  className="text-sm font-medium transition-colors hover:text-primary"
                >
                  Dashboard
                </Link>
              </nav>
            </SheetContent>
          </Sheet>

          {isLoggedIn ? (
            <div className="flex items-center gap-2">
              <Button variant="ghost" size="icon">
                <User className="h-5 w-5" />
              </Button>
              <Button
                variant="ghost"
                size="icon"
                onClick={() => setIsLoggedIn(false)}
              >
                <LogOut className="h-5 w-5" />
              </Button>
            </div>
          ) : (
            <div className="flex items-center gap-2">
              <Dialog>
                <DialogTrigger asChild>
                  <Button variant="ghost" size="sm">
                    Log in
                  </Button>
                </DialogTrigger>
                <DialogContent className="sm:max-w-[425px]">
                  <DialogHeader>
                    <DialogTitle>Welcome back</DialogTitle>
                    <DialogDescription>
                      Enter your credentials to access your account.
                    </DialogDescription>
                  </DialogHeader>
                  <div className="grid gap-4 py-4">
                    <div className="grid gap-2">
                      <Label htmlFor="email">Email</Label>
                      <Input
                        id="email"
                        type="email"
                        placeholder="name@example.com"
                      />
                    </div>
                    <div className="grid gap-2">
                      <Label htmlFor="password">Password</Label>
                      <Input id="password" type="password" />
                    </div>
                    <Button
                      onClick={() => setIsLoggedIn(true)}
                      className="w-full"
                    >
                      Log in
                    </Button>
                  </div>
                </DialogContent>
              </Dialog>

              <Dialog>
                <DialogTrigger asChild>
                  <Button size="sm">Register</Button>
                </DialogTrigger>
                <DialogContent className="sm:max-w-[425px]">
                  <DialogHeader>
                    <DialogTitle>Create account</DialogTitle>
                    <DialogDescription>
                      Sign up to start scanning your repositories.
                    </DialogDescription>
                  </DialogHeader>
                  <div className="grid gap-4 py-4">
                    <div className="grid gap-2">
                      <Label htmlFor="name">Name</Label>
                      <Input id="name" placeholder="John Doe" />
                    </div>
                    <div className="grid gap-2">
                      <Label htmlFor="register-email">Email</Label>
                      <Input
                        id="register-email"
                        type="email"
                        placeholder="name@example.com"
                      />
                    </div>
                    <div className="grid gap-2">
                      <Label htmlFor="register-password">Password</Label>
                      <Input id="register-password" type="password" />
                    </div>
                    <Button
                      onClick={() => setIsLoggedIn(true)}
                      className="w-full"
                    >
                      Create account
                    </Button>
                  </div>
                </DialogContent>
              </Dialog>
            </div>
          )}
        </div>
      </div>
    </header>
  );
}
