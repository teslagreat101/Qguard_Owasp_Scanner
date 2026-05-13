import { AuthGuard } from "@/components/auth/AuthGuard";

export default function BillingLayout({
    children,
}: {
    children: React.ReactNode;
}) {
    return <AuthGuard>{children}</AuthGuard>;
}
