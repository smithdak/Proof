import {
  BookOpen,
  FilePenLine,
  Layers,
  Package,
  Scale,
  ShieldCheck,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";

export interface NavDestination {
  path: string;
  label: string;
  description: string;
  icon: LucideIcon;
}

export const NAV_DESTINATIONS: NavDestination[] = [
  {
    path: "/overview",
    label: "Overview",
    description: "Workspace register and open ChangeSets",
    icon: BookOpen,
  },
  {
    path: "/changesets",
    label: "ChangeSets",
    description: "Edit sets awaiting validation and approval",
    icon: FilePenLine,
  },
  {
    path: "/objects",
    label: "Released content",
    description: "Objects live in released editions",
    icon: Package,
  },
  {
    path: "/releases",
    label: "Editions and Releases",
    description: "Editions cut, releases signed and delivered",
    icon: Layers,
  },
  {
    path: "/proofs",
    label: "Proofs and Evidence",
    description: "Verification reports and evidence bundles",
    icon: ShieldCheck,
  },
  {
    path: "/authority",
    label: "Authority",
    description: "Principals, delegations, and revocations",
    icon: Scale,
  },
];
