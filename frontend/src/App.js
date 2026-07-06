import "@/App.css";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import { FeedProvider } from "@/context/FeedContext";
import Navbar from "@/components/Navbar";
import Footer from "@/components/Footer";
import { Toaster } from "@/components/ui/toaster";
import Home from "@/pages/Home";
import Database from "@/pages/Database";
import EntryDetail from "@/pages/EntryDetail";
import Checker from "@/pages/Checker";
import Methodology from "@/pages/Methodology";
import NotFound from "@/pages/NotFound";

function App() {
  return (
    <div className="dark min-h-screen bg-[#09090b] text-zinc-100 font-body">
      <FeedProvider>
        <BrowserRouter>
          <Navbar />
          <main>
            <Routes>
              <Route path="/" element={<Home />} />
              <Route path="/database" element={<Database />} />
              <Route path="/database/:id" element={<EntryDetail />} />
              <Route path="/check" element={<Checker />} />
              <Route path="/methodology" element={<Methodology />} />
              <Route path="*" element={<NotFound />} />
            </Routes>
          </main>
          <Footer />
        </BrowserRouter>
      </FeedProvider>
      <Toaster />
    </div>
  );
}

export default App;
