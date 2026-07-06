import { useMemo, useRef } from 'react';
import { Canvas, useFrame } from '@react-three/fiber';
import * as THREE from 'three';
import { HOME_PAGE } from '@/constants/testIds';

function generateSpherePoints(count, radius) {
  const points = [];
  for (let i = 0; i < count; i++) {
    const phi = Math.acos(-1 + (2 * i) / count);
    const theta = Math.sqrt(count * Math.PI) * phi;
    points.push(
      new THREE.Vector3(
        radius * Math.cos(theta) * Math.sin(phi),
        radius * Math.sin(theta) * Math.sin(phi),
        radius * Math.cos(phi)
      )
    );
  }
  return points;
}

function RadarSweep({ radius }) {
  const ref = useRef();
  const geometry = useMemo(() => {
    const shape = new THREE.Shape();
    shape.moveTo(0, 0);
    shape.absarc(0, 0, radius, 0, Math.PI / 5, false);
    shape.lineTo(0, 0);
    return new THREE.ShapeGeometry(shape, 32);
  }, [radius]);

  useFrame((_, delta) => {
    if (ref.current) ref.current.rotation.y -= delta * 0.55;
  });

  return (
    <mesh ref={ref} geometry={geometry} rotation={[Math.PI / 2, 0, 0]}>
      <meshBasicMaterial
        color="#f59e0b"
        transparent
        opacity={0.16}
        side={THREE.DoubleSide}
        depthWrite={false}
      />
    </mesh>
  );
}

function NetworkGlobe() {
  const groupRef = useRef();
  const radius = 2.3;
  const points = useMemo(() => generateSpherePoints(64, radius), []);
  const blipIndices = useMemo(() => {
    const idx = new Set();
    let seed = 7;
    while (idx.size < 7) {
      seed = (seed * 9301 + 49297) % 233280;
      idx.add(Math.floor((seed / 233280) * points.length));
    }
    return idx;
  }, [points]);

  const lineGeometry = useMemo(() => {
    const positions = [];
    for (let i = 0; i < points.length; i++) {
      for (let j = i + 1; j < points.length; j++) {
        if (points[i].distanceTo(points[j]) < 1.05) {
          positions.push(points[i].x, points[i].y, points[i].z);
          positions.push(points[j].x, points[j].y, points[j].z);
        }
      }
    }
    const geo = new THREE.BufferGeometry();
    geo.setAttribute('position', new THREE.Float32BufferAttribute(positions, 3));
    return geo;
  }, [points]);

  useFrame((_, delta) => {
    if (groupRef.current) groupRef.current.rotation.y += delta * 0.09;
  });

  return (
    <group ref={groupRef}>
      <lineSegments geometry={lineGeometry}>
        <lineBasicMaterial color="#52525b" transparent opacity={0.4} />
      </lineSegments>

      {points.map((p, i) => {
        const isBlip = blipIndices.has(i);
        return (
          <mesh key={i} position={p}>
            <sphereGeometry args={[isBlip ? 0.05 : 0.026, 8, 8]} />
            <meshBasicMaterial color={isBlip ? '#ef4444' : '#a1a1aa'} />
          </mesh>
        );
      })}

      {[...blipIndices].map((i) => (
        <mesh key={`glow-${i}`} position={points[i]}>
          <sphereGeometry args={[0.13, 12, 12]} />
          <meshBasicMaterial color="#ef4444" transparent opacity={0.18} depthWrite={false} />
        </mesh>
      ))}

      <mesh rotation={[Math.PI / 2.3, 0.3, 0]}>
        <torusGeometry args={[radius, 0.004, 8, 80]} />
        <meshBasicMaterial color="#3f3f46" transparent opacity={0.5} />
      </mesh>
      <mesh rotation={[Math.PI / 1.6, 0.9, 0.4]}>
        <torusGeometry args={[radius, 0.004, 8, 80]} />
        <meshBasicMaterial color="#3f3f46" transparent opacity={0.35} />
      </mesh>

      <RadarSweep radius={radius} />
    </group>
  );
}

/**
 * Hero-only 3D visual: a rotating wireframe/particle "supply chain" globe
 * with glowing red threat blips, swept by a translucent amber radar
 * sector. Kept lightweight (no post-processing/bloom) for performance.
 */
export default function HeroRadar3D() {
  return (
    <div className="absolute inset-0" data-testid={HOME_PAGE.hero3dCanvas}>
      <Canvas camera={{ position: [0, 0, 6.2], fov: 42 }} gl={{ alpha: true, antialias: true }}>
        <ambientLight intensity={0.5} />
        <pointLight position={[4, 3, 5]} intensity={0.8} color="#ef4444" />
        <pointLight position={[-4, -2, -3]} intensity={0.4} color="#f59e0b" />
        <NetworkGlobe />
      </Canvas>
    </div>
  );
}
