import { redirect } from 'next/navigation';

/* The contribute page was folded into the homepage; keep old links working. */
export default function ContributePage() {
  redirect('/');
}
