import { Navigate, Route, Routes } from "react-router";
import { AppShell } from "./AppShell";
import { SessionProvider } from "./SessionProvider";
import OverviewPage from "@/features/overview/OverviewPage";
import ChangesetsPage from "@/features/changesets/ChangesetsPage";
import ChangesetDetailPage from "@/features/changesets/ChangesetDetailPage";
import ReleasesPage from "@/features/releases/ReleasesPage";
import ReleaseDetailPage from "@/features/releases/ReleaseDetailPage";
import ProofsPage from "@/features/proofs/ProofsPage";
import ObjectsPage from "@/features/objects/ObjectsPage";
import AuthorityPage from "@/features/authority/AuthorityPage";

export default function App() {
  return (
    <SessionProvider>
      <Routes>
        <Route element={<AppShell />}>
          <Route path="/overview" element={<OverviewPage />} />
          <Route path="/changesets" element={<ChangesetsPage />} />
          <Route
            path="/changesets/:changesetId"
            element={<ChangesetDetailPage />}
          />
          <Route path="/objects" element={<ObjectsPage />} />
          <Route path="/releases" element={<ReleasesPage />} />
          <Route
            path="/releases/:releaseId"
            element={<ReleaseDetailPage />}
          />
          <Route path="/proofs" element={<ProofsPage />} />
          <Route path="/authority" element={<AuthorityPage />} />
        </Route>
        <Route path="*" element={<Navigate to="/overview" replace />} />
      </Routes>
    </SessionProvider>
  );
}
