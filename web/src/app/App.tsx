import {
  Navigate,
  Route,
  Routes,
  useParams,
} from "react-router";
import { EmptyState, PageHeader, RegisterPanel } from "@/design-system";
import { AppShell } from "./AppShell";
import { SessionProvider } from "./SessionProvider";
import OverviewPage from "@/features/overview/OverviewPage";

export function PlaceholderPage({
  kicker,
  title,
}: {
  kicker: string;
  title: string;
}) {
  return (
    <div className="mx-auto max-w-3xl">
      <PageHeader kicker={kicker} title={title} />
      <RegisterPanel className="mt-6">
        <EmptyState
          title="Desk being fitted out"
          explanation="This surface joins the register in a later entry."
        />
      </RegisterPanel>
    </div>
  );
}

export function ChangesetDetailPlaceholder() {
  const { changesetId } = useParams();
  return (
    <div className="mx-auto max-w-3xl">
      <PageHeader
        kicker="ChangeSet"
        title="ChangeSet entry"
        meta={<span className="font-mono">{changesetId}</span>}
      />
      <RegisterPanel className="mt-6">
        <EmptyState
          title="Entry not yet legible here"
          explanation="The lifecycle rail, diff, and validation findings for this entry arrive with the ChangeSets desk."
        />
      </RegisterPanel>
    </div>
  );
}

export default function App() {
  return (
    <SessionProvider>
      <Routes>
        <Route element={<AppShell />}>
          <Route path="/overview" element={<OverviewPage />} />
          <Route
            path="/changesets"
            element={
              <PlaceholderPage kicker="Register" title="ChangeSets" />
            }
          />
          <Route
            path="/changesets/:changesetId"
            element={<ChangesetDetailPlaceholder />}
          />
          <Route
            path="/objects"
            element={
              <PlaceholderPage kicker="Register" title="Released content" />
            }
          />
          <Route
            path="/releases"
            element={
              <PlaceholderPage
                kicker="Register"
                title="Editions and Releases"
              />
            }
          />
          <Route
            path="/proofs"
            element={
              <PlaceholderPage kicker="Register" title="Proofs and Evidence" />
            }
          />
          <Route
            path="/authority"
            element={
              <PlaceholderPage kicker="Register" title="Authority" />
            }
          />
        </Route>
        <Route path="*" element={<Navigate to="/overview" replace />} />
      </Routes>
    </SessionProvider>
  );
}
